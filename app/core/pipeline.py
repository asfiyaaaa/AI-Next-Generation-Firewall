
import logging
import requests
from typing import Tuple, Optional, Any, Callable

from app.core.packet_processor import CaptureAction, PacketParser, PacketProcessor
from app.core.connection import ConnectionTable
from app.core.rules import RuleEngine, PacketInfo, Action
from app.core.nat import NATEngine
from app.dpi.engine import get_engine as get_dpi_engine
from app.TCP_Reassemble import TCPReassembler, StreamConfig, ReassembledStream

logger = logging.getLogger(__name__)
PACKET_INGEST_URL = "http://localhost:8000/api/packets/ingest"

class PipelineProcessor:
    """
    Unified Packet Processing Pipeline.
    
    Stages:
    1. Capture (WinDivert)
    2. L3/L4 Core Processing (Connection, Rules, NAT)
    3. L7 Deep Packet Inspection (AppID, IPS, Threat Intel)
    4. TCP Stream Reassembly (Suricata-inspired)
    5. Verdict Enforcement + Phase 3 Handoff
    """
    
    def __init__(
        self,
        connection_table: ConnectionTable,
        rule_engine: RuleEngine,
        nat_engine: Optional[NATEngine] = None,
        enable_dpi: bool = True,
        ignore_loopback: bool = False,
        enable_reassembly: bool = True,
        phase3_callback: Optional[Callable[[ReassembledStream], None]] = None
    ):
        self.conn_table = connection_table
        self.rule_engine = rule_engine
        self.nat_engine = nat_engine
        self.enable_dpi = enable_dpi
        self.ignore_loopback = ignore_loopback
        self.enable_reassembly = enable_reassembly
        
        # TCP Stream Reassembler (feeds Phase 3)
        if enable_reassembly:
            self.reassembler = TCPReassembler(
                config=StreamConfig(),
                phase3_callback=phase3_callback
            )
            self.reassembler.start_cleanup_thread()
            logger.info("TCP Stream Reassembler enabled (Phase 3 handoff active)")
        else:
            self.reassembler = None
        
        # Stats
        self.stats = {
            "processed": 0,
            "l3_allowed": 0,
            "l3_dropped": 0,
            "dpi_inspected": 0,
            "dpi_dropped": 0,
            "final_allowed": 0,
            "reassembly_processed": 0
        }
        
    def process_packet(self, raw: bytes, is_inbound: bool, addr: Any = None) -> Tuple[CaptureAction, Optional[bytes]]:
        """
        Main pipeline entry point.
        Callback for WinDivert capture.
        """
        self.stats["processed"] += 1
        
        # --- Stage 1: Parsing ---
        parsed = PacketParser.parse(raw, is_inbound)
        if not parsed:
            # Failed to parse, allow or drop based on policy? Default allow for stability
            return CaptureAction.ALLOW, None

        # Check loopback suppression
        if self.ignore_loopback and (parsed.src_ip.startswith("127.") or parsed.dst_ip.startswith("127.")):
            # Silently allow loopback traffic without logging or stats
            return CaptureAction.ALLOW, None
            
        # --- Stage 2: Core Processing (L3/L4) ---
        conn = self.conn_table.get(
            parsed.src_ip, parsed.src_port,
            parsed.dst_ip, parsed.dst_port,
            parsed.protocol
        )
        conn_state = conn.state.value if conn else "NEW"
        
        pkt_info = PacketInfo(
            src_ip=parsed.src_ip,
            dst_ip=parsed.dst_ip,
            src_port=parsed.src_port,
            dst_port=parsed.dst_port,
            protocol=parsed.protocol,
            is_inbound=is_inbound,
            connection_state=conn_state,
            packet_size=len(raw),
            tcp_flags=parsed.tcp_flags,
            syn=parsed.syn,
            ack=parsed.ack,
            fin=parsed.fin,
            rst=parsed.rst
        )
        
        # L3/L4 Match
        match_result = self.rule_engine.match(pkt_info)
        
        if match_result.action in (Action.DROP, Action.REJECT):
            self.stats["l3_dropped"] += 1
            reason = match_result.rule.name if match_result.rule else "Default Policy"
            logger.info(f"[VERDICT] DROP  | Source: L3/L4 Rules | Reason: {reason} | IP: {parsed.src_ip}")
            
            # Broadcast DROP to live UI
            try:
                requests.post(PACKET_INGEST_URL, json={
                    "src_ip": parsed.src_ip or "",
                    "dst_ip": parsed.dst_ip or "",
                    "src_port": parsed.src_port or 0,
                    "dst_port": parsed.dst_port or 0,
                    "protocol": "TCP" if parsed.protocol == 6 else "UDP",
                    "size": len(raw),
                    "verdict": "BLOCK",
                    "threat_type": reason
                }, timeout=0.1)
            except:
                pass
            
            return CaptureAction.DROP, None
            
        self.stats["l3_allowed"] += 1
        
        # Update connection state (simple update for now)
        # In a real system, we'd update timestamps, sequence numbers, etc.
        if not conn:
            from app.core.connection import Connection, ConnectionState
            new_conn = Connection(
                src_ip=parsed.src_ip,
                src_port=parsed.src_port,
                dst_ip=parsed.dst_ip,
                dst_port=parsed.dst_port,
                protocol=parsed.protocol,
                state=ConnectionState.NEW
            )
            self.conn_table.put(new_conn)

        # --- Stage 3: Deep Packet Inspection (L7) ---
        # Only inspect payload-carrying packets that are allowed by L3
        # Check payload size (headers ~ 20 (IP) + 20 (TCP) = 40 bytes)
        payload_len = parsed.total_length - (parsed.ip_header_len + (20 if parsed.protocol == 6 else 8))
        
        if self.enable_dpi and payload_len > 0:
            
            # Call DPI Engine
            dpi_engine = get_dpi_engine()
            if dpi_engine and dpi_engine._initialized:
                 # Clean log for inspection start
                 # logger.info(f"[DPI] Inspecting {payload_len} bytes payload from {parsed.src_ip}...")
                 
                 from app.dpi.engine import inspect_payload
                 from app.dpi.constants import Decision
                 
                 # Basic Payload Extraction (MVP)
                 # In a real system, we need TCP stream reassembly
                 # CAST TO BYTES is critical because raw might be a memoryview
                 payload_data = bytes(raw[-payload_len:])
                 
                 try:
                     verdict = inspect_payload(
                         payload=payload_data,
                         src_ip=parsed.src_ip,
                         dst_ip=parsed.dst_ip,
                         src_port=parsed.src_port,
                         dst_port=parsed.dst_port,
                         protocol="tcp" if parsed.protocol == 6 else "udp"
                     )
                     
                     if verdict.decision == Decision.BLOCK:
                         self.stats["dpi_dropped"] += 1
                         logger.info(f"[VERDICT] DROP  | Source: DPI Engine  | Reason: {verdict.reason} | Risk: {verdict.risk_score}")
                         return CaptureAction.DROP, None
                     else:
                         self.stats["dpi_inspected"] += 1
                         # Identify App
                         app_name = "Unknown"
                         if verdict.details:
                            app_name = verdict.details.get("app_identified", "Unknown")
                            
                         logger.info(f"[DPI INFO] App: {app_name} | Risk: {verdict.risk_score}")
                         
                 except Exception as e:
                     logger.error(f"[DPI Error] Inspection failed: {e}")

        # --- Stage 4: TCP Stream Reassembly (feeds Phase 3) ---
        if self.enable_reassembly and self.reassembler and parsed.protocol == 6:
            # Only reassemble TCP with payload
            if payload_len > 0:
                try:
                    # Create a packet-like object with seq/ack info for reassembler
                    # The parsed object already has tcp_seq, tcp_ack, etc.
                    # We need to add window if not present
                    if not hasattr(parsed, 'window'):
                        parsed.window = 65535  # Default window
                    if not hasattr(parsed, 'seq_num'):
                        parsed.seq_num = parsed.tcp_seq
                    if not hasattr(parsed, 'ack_num'):
                        parsed.ack_num = parsed.tcp_ack
                    
                    
                    # Get DPI verdict dict if available
                    dpi_verdict_dict = None
                    if self.enable_dpi and 'verdict' in dir():
                        dpi_verdict_dict = {
                            "decision": verdict.decision.value if hasattr(verdict, 'decision') else "allow",
                            "risk_score": getattr(verdict, 'risk_score', 0),
                            "reason": getattr(verdict, 'reason', ''),
                            "app_identified": verdict.details.get('app_identified', 'Unknown') if hasattr(verdict, 'details') and verdict.details else 'Unknown'
                        }
                    
                    self.reassembler.process_packet(parsed, payload_data, dpi_verdict_dict)
                    self.stats["reassembly_processed"] += 1
                except Exception as e:
                    logger.error(f"[Reassembly Error] {e}")

        # --- Stage 5: Final Verdict ---
        self.stats["final_allowed"] += 1
        logger.info(f"[VERDICT] ALLOW | Protocol: {parsed.protocol} | Size: {len(raw)} bytes | Source: {parsed.src_ip} -> {parsed.dst_ip}")
        
        # Broadcast ALLOW to live UI
        try:
            requests.post(PACKET_INGEST_URL, json={
                "src_ip": parsed.src_ip or "",
                "dst_ip": parsed.dst_ip or "",
                "src_port": parsed.src_port or 0,
                "dst_port": parsed.dst_port or 0,
                "protocol": "TCP" if parsed.protocol == 6 else "UDP",
                "size": len(raw),
                "verdict": "ALLOW",
                "threat_type": "None"
            }, timeout=0.1)
        except:
            pass
        
        return CaptureAction.ALLOW, None

    def get_stats(self):
        return self.stats



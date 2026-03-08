
import struct
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple, Any

# We need CaptureAction here (or in a common file). 
# To avoid circular imports, let's redefine or inspect dependency tree.
# capture.py imports PacketProcessor. If PacketProcessor imports CaptureAction from capture.py, it's circular.
# Best to move CaptureAction to 'app.core.structs' or similar, OR define Enums here and alias them?
# Let's keep Enums in packet_processor.py or move shared structs to a new file.
# For simplicity, let's assume CaptureAction is defined here or imported if safe.
# Actually, CaptureAction is simple enum. Let's define it here and have capture.py use it.

logger = logging.getLogger(__name__)

class CaptureAction(Enum):
    """Actions for captured packets"""
    ALLOW = "allow"     # Reinject packet unchanged
    DROP = "drop"       # Drop packet (don't reinject)
    MODIFY = "modify"   # Reinject modified packet

class Protocol(Enum):
    """IP Protocol numbers"""
    ICMP = 1
    TCP = 6
    UDP = 17

@dataclass
class ParsedPacket:
    """Parsed packet information"""
    raw: bytes
    ip_version: int = 4
    ip_header_len: int = 20
    total_length: int = 0
    protocol: int = 0
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    
    # TCP specific
    tcp_flags: str = ""
    tcp_seq: int = 0
    tcp_ack: int = 0
    syn: bool = False
    ack: bool = False
    fin: bool = False
    rst: bool = False
    psh: bool = False
    urg: bool = False
    
    # Direction
    is_inbound: bool = True

class PacketParser:
    """Parse raw IP packets into structured data."""
    
    @staticmethod
    def parse(raw: bytes, is_inbound: bool = True) -> Optional[ParsedPacket]:
        """Parse raw packet bytes."""
        if len(raw) < 20:
            return None
        
        try:
            version_ihl = raw[0]
            version = (version_ihl >> 4) & 0x0F
            ihl = (version_ihl & 0x0F) * 4
            
            if version != 4:
                return None
            
            total_length = struct.unpack(">H", raw[2:4])[0]
            protocol = raw[9]
            src_ip = ".".join(str(b) for b in raw[12:16])
            dst_ip = ".".join(str(b) for b in raw[16:20])
            
            packet = ParsedPacket(
                raw=raw,
                ip_version=version,
                ip_header_len=ihl,
                total_length=total_length,
                protocol=protocol,
                src_ip=src_ip,
                dst_ip=dst_ip,
                is_inbound=is_inbound
            )
            
            if protocol == Protocol.TCP.value:
                PacketParser._parse_tcp(raw, ihl, packet)
            elif protocol == Protocol.UDP.value:
                PacketParser._parse_udp(raw, ihl, packet)
            
            return packet
            
        except Exception as e:
            logger.debug(f"Packet parse error: {e}")
            return None
    
    @staticmethod
    def _parse_tcp(raw: bytes, offset: int, packet: ParsedPacket) -> None:
        """Parse TCP header"""
        if len(raw) < offset + 20:
            return
        
        tcp_header = raw[offset:offset + 20]
        packet.src_port = struct.unpack(">H", tcp_header[0:2])[0]
        packet.dst_port = struct.unpack(">H", tcp_header[2:4])[0]
        packet.tcp_seq = struct.unpack(">I", tcp_header[4:8])[0]
        packet.tcp_ack = struct.unpack(">I", tcp_header[8:12])[0]
        
        flags = tcp_header[13]
        packet.fin = bool(flags & 0x01)
        packet.syn = bool(flags & 0x02)
        packet.rst = bool(flags & 0x04)
        packet.psh = bool(flags & 0x08)
        packet.ack = bool(flags & 0x10)
        packet.urg = bool(flags & 0x20)
        
        flag_chars = []
        if packet.syn: flag_chars.append('S')
        if packet.ack: flag_chars.append('A')
        if packet.fin: flag_chars.append('F')
        if packet.rst: flag_chars.append('R')
        if packet.psh: flag_chars.append('P')
        if packet.urg: flag_chars.append('U')
        packet.tcp_flags = ''.join(flag_chars)
    
    @staticmethod
    def _parse_udp(raw: bytes, offset: int, packet: ParsedPacket) -> None:
        """Parse UDP header"""
        if len(raw) < offset + 8:
            return
        
        udp_header = raw[offset:offset + 8]
        packet.src_port = struct.unpack(">H", udp_header[0:2])[0]
        packet.dst_port = struct.unpack(">H", udp_header[2:4])[0]


class PacketProcessor:
    """
    Central packet processing pipeline.
    
    Order of processing:
    1. Parse packet headers
    2. Check connection table
    3. Match against rules
    4. Apply NAT if configured
    5. Update connection state
    6. Return action (ALLOW/DROP)
    """
    
    def __init__(self, connection_table, rule_engine, nat_engine=None):
        self.conn_table = connection_table
        self.rule_engine = rule_engine
        self.nat_engine = nat_engine
        
        self.packets_processed = 0
        self.packets_allowed = 0
        self.packets_dropped = 0
        self.parse_errors = 0
    
    def process(self, raw: bytes, is_inbound: bool, addr: Any = None) -> Tuple[CaptureAction, Optional[bytes]]:
        """Process a packet through the firewall pipeline."""
        self.packets_processed += 1
        
        parsed = PacketParser.parse(raw, is_inbound)
        if not parsed:
            self.parse_errors += 1
            return CaptureAction.ALLOW, None
        
        # Import here to avoid circular dependency
        from .rules import Action
        
        # Check connection state
        conn = self.conn_table.get(
            parsed.src_ip, parsed.src_port,
            parsed.dst_ip, parsed.dst_port,
            parsed.protocol
        )
        conn_state = conn.state.value if conn else "NEW"
        
        # Create packet info for rule matching
        from .rules import PacketInfo
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
        
        # Match rules
        match_result = self.rule_engine.match(pkt_info)
        
        if match_result.action in (Action.DROP, Action.REJECT):
            self.packets_dropped += 1
            return CaptureAction.DROP, None
        
        self.packets_allowed += 1
        return CaptureAction.ALLOW, None
    
    def get_stats(self) -> dict:
        return {
            "packets_processed": self.packets_processed,
            "packets_allowed": self.packets_allowed,
            "packets_dropped": self.packets_dropped,
            "parse_errors": self.parse_errors
        }

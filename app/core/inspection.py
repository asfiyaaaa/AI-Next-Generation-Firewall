"""
Inspection Module - Stateful Packet Inspection & Attack Detection

Consolidates:
- SPI Engine (TCP/UDP/ICMP state tracking)
- Attack Detector (SYN scan, ACK scan, SYN flood detection)

Features:
- TCP connection state machine (SYN, ESTABLISHED, FIN, etc.)
- UDP pseudo-connection tracking
- ICMP ping/pong tracking  
- Thread-safe attack pattern detection
"""

import time
import threading
import logging
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass, field


logger = logging.getLogger(__name__)


# =============================================================================
# Attack Detection
# =============================================================================

@dataclass
class AttackStats:
    """Statistics for attack detection"""
    syn_scans_detected: int = 0
    ack_scans_detected: int = 0
    syn_floods_detected: int = 0
    total_alerts: int = 0


class AttackDetector:
    """
    Thread-safe attack detection engine.
    
    Detects:
    - SYN scan (many SYN packets from same IP)
    - ACK scan (ACK packets without established connection)
    - SYN flood (half-open connections)
    """
    
    def __init__(
        self,
        window: int = 10,
        syn_threshold: int = 20,
        ack_threshold: int = 20,
        half_open_threshold: int = 15,
        max_tracked_ips: int = 10000
    ):
        self.window = window
        self.syn_threshold = syn_threshold
        self.ack_threshold = ack_threshold
        self.half_open_threshold = half_open_threshold
        self.max_tracked_ips = max_tracked_ips
        
        self._syn_count: Dict[str, List[float]] = {}
        self._ack_count: Dict[str, List[float]] = {}
        self._half_open: Dict[str, int] = {}
        
        self._syn_lock = threading.Lock()
        self._ack_lock = threading.Lock()
        self._half_open_lock = threading.Lock()
        
        self.stats = AttackStats()
        self._stats_lock = threading.Lock()
    
    def _cleanup_timestamps(self, counter: Dict[str, List[float]], lock: threading.Lock) -> None:
        now = time.time()
        cutoff = now - self.window
        
        with lock:
            expired_ips = []
            for ip, timestamps in counter.items():
                counter[ip] = [t for t in timestamps if t > cutoff]
                if not counter[ip]:
                    expired_ips.append(ip)
            
            for ip in expired_ips:
                del counter[ip]
            
            if len(counter) > self.max_tracked_ips:
                oldest_ips = sorted(counter.keys(), key=lambda ip: min(counter[ip]) if counter[ip] else 0)[:len(counter) - self.max_tracked_ips]
                for ip in oldest_ips:
                    del counter[ip]
    
    def record_syn(self, ip: str) -> Optional[str]:
        now = time.time()
        with self._syn_lock:
            if ip not in self._syn_count:
                self._syn_count[ip] = []
            self._syn_count[ip].append(now)
        
        self._cleanup_timestamps(self._syn_count, self._syn_lock)
        
        with self._syn_lock:
            if ip in self._syn_count and len(self._syn_count[ip]) >= self.syn_threshold:
                with self._stats_lock:
                    self.stats.syn_scans_detected += 1
                    self.stats.total_alerts += 1
                return f"SYN_SCAN detected from {ip}"
        return None
    
    def record_ack(self, ip: str) -> Optional[str]:
        now = time.time()
        with self._ack_lock:
            if ip not in self._ack_count:
                self._ack_count[ip] = []
            self._ack_count[ip].append(now)
        
        self._cleanup_timestamps(self._ack_count, self._ack_lock)
        
        with self._ack_lock:
            if ip in self._ack_count and len(self._ack_count[ip]) >= self.ack_threshold:
                with self._stats_lock:
                    self.stats.ack_scans_detected += 1
                    self.stats.total_alerts += 1
                return f"ACK_SCAN detected from {ip}"
        return None
    
    def record_half_open(self, ip: str) -> Optional[str]:
        with self._half_open_lock:
            if ip not in self._half_open:
                self._half_open[ip] = 0
            self._half_open[ip] += 1
            
            if self._half_open.get(ip, 0) >= self.half_open_threshold:
                with self._stats_lock:
                    self.stats.syn_floods_detected += 1
                    self.stats.total_alerts += 1
                return f"SYN_FLOOD detected from {ip}"
        return None
    
    def clear_half_open(self, ip: str) -> None:
        with self._half_open_lock:
            if ip in self._half_open:
                self._half_open[ip] = 0
    
    def analyze_packet(self, src_ip: str, flags: str, spi_state: str) -> Optional[str]:
        if flags == "S" and spi_state in ("NO_STATE", "CLOSED", "NEW"):
            alert = self.record_syn(src_ip)
            if alert:
                return alert
        
        if "A" in flags and spi_state not in ("ESTABLISHED", "SYN_SENT", "SYN_RECV"):
            alert = self.record_ack(src_ip)
            if alert:
                return alert
        
        if flags == "S" and spi_state == "SYN_SENT":
            alert = self.record_half_open(src_ip)
            if alert:
                return alert
        
        if spi_state == "ESTABLISHED":
            self.clear_half_open(src_ip)
        
        return None
    
    def get_stats(self) -> dict:
        with self._stats_lock:
            return {
                "syn_scans_detected": self.stats.syn_scans_detected,
                "ack_scans_detected": self.stats.ack_scans_detected,
                "syn_floods_detected": self.stats.syn_floods_detected,
                "total_alerts": self.stats.total_alerts,
            }
    
    def reset(self) -> None:
        with self._syn_lock:
            self._syn_count.clear()
        with self._ack_lock:
            self._ack_count.clear()
        with self._half_open_lock:
            self._half_open.clear()
        with self._stats_lock:
            self.stats = AttackStats()


# Global instance for backward compatibility
_default_detector = AttackDetector()

def record_syn(ip: str) -> Optional[str]:
    return _default_detector.record_syn(ip)

def record_ack(ip: str) -> Optional[str]:
    return _default_detector.record_ack(ip)

def record_half_open(ip: str) -> Optional[str]:
    return _default_detector.record_half_open(ip)

def clear_half_open(ip: str) -> None:
    _default_detector.clear_half_open(ip)

def analyze_packet(src_ip: str, flags: str, spi_state: str) -> Optional[str]:
    return _default_detector.analyze_packet(src_ip, flags, spi_state)


# =============================================================================
# Stateful Packet Inspection
# =============================================================================

@dataclass 
class InspectionResult:
    """Result of stateful packet inspection"""
    state: str
    allowed: bool
    attack_detected: Optional[str] = None
    reason: str = ""
    
    def __bool__(self) -> bool:
        return self.allowed


class SPIEngine:
    """
    Stateful Packet Inspection Engine.
    
    Provides:
    - TCP connection state tracking (3-way handshake, established, closing)
    - UDP pseudo-connection tracking
    - ICMP tracking for ping/pong
    - Attack detection integration
    """
    
    def __init__(self, connection_table):
        self.conn_table = connection_table
        
        self.allow_new_connections = True
        self.strict_tcp_validation = True
        self.track_udp = True
        self.track_icmp = True
        
        self.syn_flood_threshold = 20
        self.ack_scan_threshold = 20
        
        self.packets_inspected = 0
        self.new_connections = 0
        self.established_packets = 0
        self.invalid_packets = 0
        self.attacks_detected = 0
    
    def inspect(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: int,
        tcp_flags: str = "",
        is_inbound: bool = True,
        packet_size: int = 0
    ) -> InspectionResult:
        """Perform stateful inspection on a packet."""
        self.packets_inspected += 1
        
        if protocol == 6:  # TCP
            return self._inspect_tcp(src_ip, src_port, dst_ip, dst_port, tcp_flags, is_inbound, packet_size)
        elif protocol == 17:  # UDP
            return self._inspect_udp(src_ip, src_port, dst_ip, dst_port, is_inbound, packet_size)
        elif protocol == 1:  # ICMP
            return self._inspect_icmp(src_ip, dst_ip, is_inbound, packet_size)
        else:
            return InspectionResult(state="UNTRACKED", allowed=True, reason="Protocol not tracked")
    
    def _inspect_tcp(self, src_ip, src_port, dst_ip, dst_port, flags, is_inbound, packet_size) -> InspectionResult:
        from .connection import Connection, ConnectionState
        
        # Check attack patterns
        attack = self._check_tcp_attacks(src_ip, flags)
        if attack:
            self.attacks_detected += 1
            return InspectionResult(state="ATTACK", allowed=False, attack_detected=attack, reason=f"Attack: {attack}")
        
        conn = self.conn_table.get(src_ip, src_port, dst_ip, dst_port, 6)
        rev_conn = None
        if not conn:
            rev_conn = self.conn_table.get(dst_ip, dst_port, src_ip, src_port, 6)
        
        syn = 'S' in flags and 'A' not in flags
        syn_ack = 'S' in flags and 'A' in flags
        ack = 'A' in flags and 'S' not in flags
        fin = 'F' in flags
        rst = 'R' in flags
        
        if conn:
            return self._update_tcp_state(conn, flags, syn, syn_ack, ack, fin, rst, packet_size)
        
        if rev_conn:
            return self._handle_tcp_response(rev_conn, flags, syn_ack, packet_size)
        
        if syn:
            if not self.allow_new_connections:
                return InspectionResult(state="NEW_BLOCKED", allowed=False, reason="New connections blocked")
            
            new_conn = Connection(
                src_ip=src_ip, src_port=src_port,
                dst_ip=dst_ip, dst_port=dst_port,
                protocol=6, state=ConnectionState.SYN_SENT
            )
            self.conn_table.put(new_conn)
            self.new_connections += 1
            record_half_open(src_ip)
            
            return InspectionResult(state="NEW", allowed=True, reason="New TCP connection")
        
        if self.strict_tcp_validation:
            self.invalid_packets += 1
            return InspectionResult(state="INVALID", allowed=False, reason="TCP without established connection")
        
        return InspectionResult(state="ASSUMED_ESTABLISHED", allowed=True, reason="Assumed mid-stream")
    
    def _update_tcp_state(self, conn, flags, syn, syn_ack, ack, fin, rst, packet_size) -> InspectionResult:
        from .connection import ConnectionState
        
        conn.last_seen = time.time()
        
        if rst:
            self.conn_table.delete(conn.src_ip, conn.src_port, conn.dst_ip, conn.dst_port, 6)
            return InspectionResult(state="CLOSED", allowed=True, reason="RST")
        
        if conn.state == ConnectionState.SYN_SENT:
            if syn_ack:
                conn.state = ConnectionState.ESTABLISHED
                conn.is_assured = True
                clear_half_open(conn.src_ip)
                self.established_packets += 1
                return InspectionResult(state="ESTABLISHED", allowed=True, reason="Handshake complete")
        
        elif conn.state == ConnectionState.ESTABLISHED:
            if fin:
                conn.state = ConnectionState.FIN_WAIT
                return InspectionResult(state="FIN_WAIT", allowed=True, reason="Connection closing")
            
            conn.update_stats(packet_size, is_inbound=True)
            self.established_packets += 1
            return InspectionResult(state="ESTABLISHED", allowed=True, reason="Established")
        
        return InspectionResult(state=conn.state.value, allowed=True, reason="Tracked")
    
    def _handle_tcp_response(self, conn, flags, syn_ack, packet_size) -> InspectionResult:
        from .connection import ConnectionState
        
        conn.last_seen = time.time()
        
        if syn_ack and conn.state == ConnectionState.SYN_SENT:
            conn.state = ConnectionState.ESTABLISHED
            conn.is_assured = True
            clear_half_open(conn.src_ip)
            self.established_packets += 1
            return InspectionResult(state="ESTABLISHED", allowed=True, reason="SYN-ACK response")
        
        if conn.state == ConnectionState.ESTABLISHED:
            conn.update_stats(packet_size, is_inbound=True)
            self.established_packets += 1
            return InspectionResult(state="ESTABLISHED", allowed=True, reason="Response")
        
        return InspectionResult(state=conn.state.value, allowed=True, reason="Related")
    
    def _check_tcp_attacks(self, src_ip: str, flags: str) -> Optional[str]:
        if 'S' in flags and 'A' not in flags:
            attack = record_syn(src_ip)
            if attack:
                return attack
        
        if flags == 'A':
            attack = record_ack(src_ip)
            if attack:
                return attack
        
        return None
    
    def _inspect_udp(self, src_ip, src_port, dst_ip, dst_port, is_inbound, packet_size) -> InspectionResult:
        from .connection import Connection, ConnectionState
        
        if not self.track_udp:
            return InspectionResult(state="UNTRACKED", allowed=True, reason="UDP tracking disabled")
        
        conn = self.conn_table.get(src_ip, src_port, dst_ip, dst_port, 17)
        if conn:
            conn.last_seen = time.time()
            return InspectionResult(state="UDP_ESTABLISHED", allowed=True, reason="Known UDP flow")
        
        rev_conn = self.conn_table.get(dst_ip, dst_port, src_ip, src_port, 17)
        if rev_conn:
            rev_conn.last_seen = time.time()
            return InspectionResult(state="UDP_ESTABLISHED", allowed=True, reason="UDP response")
        
        if self.allow_new_connections:
            new_conn = Connection(
                src_ip=src_ip, src_port=src_port,
                dst_ip=dst_ip, dst_port=dst_port,
                protocol=17, state=ConnectionState.UDP_NEW
            )
            self.conn_table.put(new_conn)
            self.new_connections += 1
            return InspectionResult(state="UDP_NEW", allowed=True, reason="New UDP flow")
        
        return InspectionResult(state="NEW_BLOCKED", allowed=False, reason="New UDP blocked")
    
    def _inspect_icmp(self, src_ip, dst_ip, is_inbound, packet_size) -> InspectionResult:
        from .connection import Connection, ConnectionState
        
        if not self.track_icmp:
            return InspectionResult(state="UNTRACKED", allowed=True, reason="ICMP tracking disabled")
        
        conn = self.conn_table.get(src_ip, 0, dst_ip, 0, 1)
        if conn:
            conn.last_seen = time.time()
            return InspectionResult(state="ICMP_ESTABLISHED", allowed=True, reason="Known ICMP")
        
        rev_conn = self.conn_table.get(dst_ip, 0, src_ip, 0, 1)
        if rev_conn:
            return InspectionResult(state="ICMP_REPLY", allowed=True, reason="ICMP reply")
        
        if self.allow_new_connections:
            new_conn = Connection(
                src_ip=src_ip, src_port=0,
                dst_ip=dst_ip, dst_port=0,
                protocol=1, state=ConnectionState.ICMP_NEW
            )
            self.conn_table.put(new_conn)
            return InspectionResult(state="ICMP_NEW", allowed=True, reason="New ICMP")
        
        return InspectionResult(state="NEW_BLOCKED", allowed=False, reason="New ICMP blocked")
    
    def get_stats(self) -> dict:
        return {
            "packets_inspected": self.packets_inspected,
            "new_connections": self.new_connections,
            "established_packets": self.established_packets,
            "invalid_packets": self.invalid_packets,
            "attacks_detected": self.attacks_detected,
            "connection_table": self.conn_table.get_stats()
        }
    
    def __repr__(self) -> str:
        return f"SPIEngine(inspected={self.packets_inspected})"

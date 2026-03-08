"""
NAT Module - Network Address Translation

Consolidates:
- Port Pool: Ephemeral port allocation for NAT
- NAT Table: Mapping storage with bidirectional lookup
- NAT Engine: SNAT, DNAT, Masquerade translation

Features:
- SNAT (Source NAT) for outbound traffic masquerading
- DNAT (Destination NAT) for port forwarding
- Thread-safe port allocation with automatic expiration
- LRU eviction for mapping table
"""

import struct
import threading
import time
import random
import logging
from typing import Optional, List, Dict, Set, Tuple
from dataclasses import dataclass, field
from collections import OrderedDict
from enum import Enum
from ipaddress import ip_network, ip_address


logger = logging.getLogger(__name__)


# =============================================================================
# Checksum Utilities
# =============================================================================

def _calculate_checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data = data + b'\x00'
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return ~checksum & 0xFFFF


def _recalc_ip_checksum(packet: bytearray) -> None:
    ihl = (packet[0] & 0x0F) * 4
    packet[10:12] = b'\x00\x00'
    checksum = _calculate_checksum(bytes(packet[:ihl]))
    packet[10:12] = struct.pack('>H', checksum)


def _recalc_tcp_checksum(packet: bytearray) -> None:
    ihl = (packet[0] & 0x0F) * 4
    tcp_length = len(packet) - ihl
    pseudo_header = packet[12:16] + packet[16:20] + b'\x00' + bytes([6]) + struct.pack('>H', tcp_length)
    packet[ihl + 16:ihl + 18] = b'\x00\x00'
    checksum = _calculate_checksum(pseudo_header + packet[ihl:])
    packet[ihl + 16:ihl + 18] = struct.pack('>H', checksum)


def _recalc_udp_checksum(packet: bytearray) -> None:
    ihl = (packet[0] & 0x0F) * 4
    udp_length = len(packet) - ihl
    pseudo_header = packet[12:16] + packet[16:20] + b'\x00' + bytes([17]) + struct.pack('>H', udp_length)
    packet[ihl + 6:ihl + 8] = b'\x00\x00'
    checksum = _calculate_checksum(pseudo_header + packet[ihl:])
    if checksum == 0:
        checksum = 0xFFFF
    packet[ihl + 6:ihl + 8] = struct.pack('>H', checksum)


# =============================================================================
# Port Pool
# =============================================================================

@dataclass
class PortAllocation:
    port: int
    allocated_at: float
    last_used: float
    key: str


class PortPool:
    """Thread-safe port pool for NAT translations."""
    
    def __init__(self, start: int = 10000, end: int = 65535, expiration: int = 300):
        self.start = start
        self.end = end
        self.expiration = expiration
        self.available: Set[int] = set(range(start, end + 1))
        self.in_use: Dict[int, PortAllocation] = {}
        self.key_to_port: Dict[str, int] = {}
        self.lock = threading.RLock()
        self.total_allocations = 0
        self.total_releases = 0
        self.total_expirations = 0
    
    def allocate(self, key: Optional[str] = None) -> Optional[int]:
        with self.lock:
            if key and key in self.key_to_port:
                port = self.key_to_port[key]
                if port in self.in_use:
                    self.in_use[port].last_used = time.time()
                return port
            
            if not self.available:
                self._reclaim_expired()
                if not self.available:
                    return None
            
            port = random.choice(list(self.available))
            self.available.remove(port)
            self.in_use[port] = PortAllocation(port=port, allocated_at=time.time(), last_used=time.time(), key=key or "")
            if key:
                self.key_to_port[key] = port
            self.total_allocations += 1
            return port
    
    def release(self, port: int) -> bool:
        with self.lock:
            if port not in self.in_use:
                return False
            allocation = self.in_use[port]
            if allocation.key and allocation.key in self.key_to_port:
                del self.key_to_port[allocation.key]
            del self.in_use[port]
            self.available.add(port)
            self.total_releases += 1
            return True
    
    def _reclaim_expired(self) -> int:
        current_time = time.time()
        expired_ports = [p for p, a in self.in_use.items() if current_time - a.last_used > self.expiration]
        for port in expired_ports:
            allocation = self.in_use[port]
            if allocation.key and allocation.key in self.key_to_port:
                del self.key_to_port[allocation.key]
            del self.in_use[port]
            self.available.add(port)
            self.total_expirations += 1
        return len(expired_ports)
    
    def cleanup_expired(self) -> int:
        with self.lock:
            return self._reclaim_expired()
    
    def get_stats(self) -> dict:
        with self.lock:
            total = self.end - self.start + 1
            return {
                "range": f"{self.start}-{self.end}",
                "available": len(self.available),
                "in_use": len(self.in_use),
                "utilization": round(len(self.in_use) / total * 100, 2),
                "total_allocations": self.total_allocations,
            }


# =============================================================================
# NAT Table
# =============================================================================

@dataclass
class NATMapping:
    original_src_ip: str
    original_src_port: int
    original_dst_ip: str
    original_dst_port: int
    protocol: int
    translated_src_ip: str
    translated_src_port: int
    translated_dst_ip: Optional[str] = None
    translated_dst_port: Optional[int] = None
    nat_type: str = "snat"
    created: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    packets_in: int = 0
    packets_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    
    def get_internal_key(self) -> str:
        return f"{self.protocol}:{self.original_src_ip}:{self.original_src_port}-{self.original_dst_ip}:{self.original_dst_port}"
    
    def get_external_key(self) -> str:
        return f"{self.protocol}:{self.original_dst_ip}:{self.original_dst_port}-{self.translated_src_ip}:{self.translated_src_port}"
    
    def update_stats(self, bytes_count: int, is_inbound: bool) -> None:
        self.last_used = time.time()
        if is_inbound:
            self.packets_in += 1
            self.bytes_in += bytes_count
        else:
            self.packets_out += 1
            self.bytes_out += bytes_count


class NATTable:
    """NAT mapping table with bidirectional lookup and LRU eviction."""
    
    def __init__(self, max_mappings: int = 500000, timeout: int = 300, tcp_timeout: int = 7200, udp_timeout: int = 180):
        self.max_mappings = max_mappings
        self.default_timeout = timeout
        self.tcp_timeout = tcp_timeout
        self.udp_timeout = udp_timeout
        self.mappings: OrderedDict[str, NATMapping] = OrderedDict()
        self.reverse_index: Dict[str, str] = {}
        self.lock = threading.RLock()
        self.total_adds = 0
        self.total_lookups = 0
        self.total_hits = 0
        self.total_evictions = 0
    
    def add(self, mapping: NATMapping) -> bool:
        internal_key = mapping.get_internal_key()
        external_key = mapping.get_external_key()
        with self.lock:
            is_new = internal_key not in self.mappings
            if is_new:
                while len(self.mappings) >= self.max_mappings:
                    self._evict_one()
            else:
                self.mappings.move_to_end(internal_key)
            self.mappings[internal_key] = mapping
            self.reverse_index[external_key] = internal_key
            if is_new:
                self.total_adds += 1
            return is_new
    
    def lookup_internal(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: int) -> Optional[NATMapping]:
        key = f"{protocol}:{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        with self.lock:
            self.total_lookups += 1
            if key in self.mappings:
                self.mappings.move_to_end(key)
                mapping = self.mappings[key]
                mapping.last_used = time.time()
                self.total_hits += 1
                return mapping
            return None
    
    def lookup_external(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: int) -> Optional[NATMapping]:
        external_key = f"{protocol}:{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        with self.lock:
            self.total_lookups += 1
            if external_key in self.reverse_index:
                internal_key = self.reverse_index[external_key]
                if internal_key in self.mappings:
                    self.mappings.move_to_end(internal_key)
                    mapping = self.mappings[internal_key]
                    mapping.last_used = time.time()
                    self.total_hits += 1
                    return mapping
            return None
    
    def _evict_one(self) -> None:
        if self.mappings:
            key, mapping = self.mappings.popitem(last=False)
            external_key = mapping.get_external_key()
            if external_key in self.reverse_index:
                del self.reverse_index[external_key]
            self.total_evictions += 1
    
    def cleanup_expired(self) -> int:
        current_time = time.time()
        expired_keys = []
        with self.lock:
            for key, mapping in self.mappings.items():
                timeout = self.tcp_timeout if mapping.protocol == 6 else self.udp_timeout
                if (current_time - mapping.last_used) > timeout:
                    expired_keys.append(key)
            for key in expired_keys:
                mapping = self.mappings[key]
                del self.mappings[key]
                external_key = mapping.get_external_key()
                if external_key in self.reverse_index:
                    del self.reverse_index[external_key]
        return len(expired_keys)
    
    def get_stats(self) -> dict:
        with self.lock:
            return {
                "current_mappings": len(self.mappings),
                "max_mappings": self.max_mappings,
                "total_adds": self.total_adds,
                "total_hits": self.total_hits,
            }
    
    def __len__(self) -> int:
        return len(self.mappings)


# =============================================================================
# NAT Engine
# =============================================================================

class NATType(Enum):
    SNAT = "snat"
    DNAT = "dnat"
    MASQUERADE = "masq"
    REDIRECT = "redirect"


@dataclass
class NATRule:
    id: int
    nat_type: NATType
    enabled: bool = True
    priority: int = 100
    match_src: Optional[str] = None
    match_dst: Optional[str] = None
    match_sport: Optional[int] = None
    match_dport: Optional[int] = None
    match_protocol: Optional[int] = None
    translate_src: Optional[str] = None
    translate_sport: Optional[int] = None
    translate_dst: Optional[str] = None
    translate_dport: Optional[int] = None
    hit_count: int = 0
    byte_count: int = 0
    
    def matches(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: int) -> bool:
        if self.match_protocol is not None and self.match_protocol != protocol:
            return False
        if self.match_src and not self._ip_in_cidr(src_ip, self.match_src):
            return False
        if self.match_dst and not self._ip_in_cidr(dst_ip, self.match_dst):
            return False
        if self.match_sport is not None and self.match_sport != src_port:
            return False
        if self.match_dport is not None and self.match_dport != dst_port:
            return False
        return True
    
    def _ip_in_cidr(self, ip: str, cidr: str) -> bool:
        try:
            return ip_address(ip) in ip_network(cidr, strict=False)
        except ValueError:
            return False


class NATEngine:
    """NAT Engine for packet translation (SNAT, DNAT, Masquerade)."""
    
    def __init__(self, external_ip: str = "0.0.0.0", port_range: Tuple[int, int] = (10000, 65535), max_mappings: int = 500000):
        self.external_ip = external_ip
        self.nat_table = NATTable(max_mappings=max_mappings)
        self.port_pool = PortPool(start=port_range[0], end=port_range[1])
        self.rules: List[NATRule] = []
        self._next_rule_id = 1
        self.translations_out = 0
        self.translations_in = 0
        self.cache_hits = 0
        self.new_mappings = 0
    
    def add_rule(self, rule: NATRule) -> None:
        if rule.id == 0:
            rule.id = self._next_rule_id
            self._next_rule_id += 1
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority)
    
    def translate_outbound(self, raw_packet: bytes, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: int) -> Optional[bytes]:
        mapping = self.nat_table.lookup_internal(src_ip, src_port, dst_ip, dst_port, protocol)
        if mapping:
            self.cache_hits += 1
            mapping.update_stats(len(raw_packet), is_inbound=False)
            return self._apply_snat(raw_packet, mapping)
        
        for rule in self.rules:
            if not rule.enabled or rule.nat_type not in (NATType.SNAT, NATType.MASQUERADE):
                continue
            if rule.matches(src_ip, src_port, dst_ip, dst_port, protocol):
                mapping = self._create_snat_mapping(rule, src_ip, src_port, dst_ip, dst_port, protocol)
                if mapping:
                    self.nat_table.add(mapping)
                    self.new_mappings += 1
                    rule.hit_count += 1
                    self.translations_out += 1
                    return self._apply_snat(raw_packet, mapping)
        return None
    
    def translate_inbound(self, raw_packet: bytes, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: int) -> Optional[bytes]:
        mapping = self.nat_table.lookup_external(src_ip, src_port, dst_ip, dst_port, protocol)
        if mapping:
            self.cache_hits += 1
            mapping.update_stats(len(raw_packet), is_inbound=True)
            self.translations_in += 1
            return self._apply_reverse_snat(raw_packet, mapping)
        
        for rule in self.rules:
            if not rule.enabled or rule.nat_type != NATType.DNAT:
                continue
            if rule.matches(src_ip, src_port, dst_ip, dst_port, protocol):
                rule.hit_count += 1
                self.translations_in += 1
                return self._apply_dnat(raw_packet, rule)
        return None
    
    def _create_snat_mapping(self, rule: NATRule, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: int) -> Optional[NATMapping]:
        translate_ip = rule.translate_src or self.external_ip
        conn_key = f"{protocol}:{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        translate_port = self.port_pool.allocate(conn_key)
        if translate_port is None:
            return None
        return NATMapping(
            original_src_ip=src_ip, original_src_port=src_port,
            original_dst_ip=dst_ip, original_dst_port=dst_port,
            protocol=protocol, translated_src_ip=translate_ip, translated_src_port=translate_port,
            nat_type=rule.nat_type.value
        )
    
    def _apply_snat(self, raw_packet: bytes, mapping: NATMapping) -> bytes:
        packet = bytearray(raw_packet)
        packet[12:16] = bytes([int(x) for x in mapping.translated_src_ip.split('.')])
        ihl = (packet[0] & 0x0F) * 4
        packet[ihl:ihl+2] = struct.pack(">H", mapping.translated_src_port)
        _recalc_ip_checksum(packet)
        if mapping.protocol == 6:
            _recalc_tcp_checksum(packet)
        elif mapping.protocol == 17:
            _recalc_udp_checksum(packet)
        return bytes(packet)
    
    def _apply_reverse_snat(self, raw_packet: bytes, mapping: NATMapping) -> bytes:
        packet = bytearray(raw_packet)
        packet[16:20] = bytes([int(x) for x in mapping.original_src_ip.split('.')])
        ihl = (packet[0] & 0x0F) * 4
        packet[ihl+2:ihl+4] = struct.pack(">H", mapping.original_src_port)
        _recalc_ip_checksum(packet)
        if mapping.protocol == 6:
            _recalc_tcp_checksum(packet)
        elif mapping.protocol == 17:
            _recalc_udp_checksum(packet)
        return bytes(packet)
    
    def _apply_dnat(self, raw_packet: bytes, rule: NATRule) -> bytes:
        packet = bytearray(raw_packet)
        if rule.translate_dst:
            packet[16:20] = bytes([int(x) for x in rule.translate_dst.split('.')])
        ihl = (packet[0] & 0x0F) * 4
        protocol = packet[9]
        if rule.translate_dport:
            packet[ihl+2:ihl+4] = struct.pack(">H", rule.translate_dport)
        _recalc_ip_checksum(packet)
        if protocol == 6:
            _recalc_tcp_checksum(packet)
        elif protocol == 17:
            _recalc_udp_checksum(packet)
        return bytes(packet)
    
    def get_stats(self) -> dict:
        return {
            "external_ip": self.external_ip,
            "rules_count": len(self.rules),
            "translations_out": self.translations_out,
            "translations_in": self.translations_in,
            "nat_table": self.nat_table.get_stats(),
            "port_pool": self.port_pool.get_stats()
        }

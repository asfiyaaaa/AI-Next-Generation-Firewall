"""
Data Structures Module - High-Performance Data Structures

Consolidates:
- Flow Cache: Fast-path caching for established flows
- IP Set: Efficient IP/CIDR matching with CIDR trees

Features:
- O(1) flow cache lookup with LRU eviction
- Bidirectional flow tracking
- O(log n) CIDR lookup with metadata support
- Well-known IP sets for common networks
"""

import threading
import time
import logging
from typing import Optional, Dict, Set, List, Any
from dataclasses import dataclass, field
from collections import OrderedDict
from enum import Enum
from ipaddress import ip_address, ip_network, IPv4Address, IPv4Network


logger = logging.getLogger(__name__)


# =============================================================================
# Flow Cache
# =============================================================================

class CachedAction(Enum):
    ALLOW = "allow"
    DROP = "drop"
    NAT = "nat"


@dataclass
class CacheEntry:
    action: CachedAction
    timestamp: float = field(default_factory=time.time)
    hit_count: int = 0
    nat_mapping: Optional[Dict] = None
    rule_id: Optional[int] = None
    
    def is_expired(self, ttl: int) -> bool:
        return (time.time() - self.timestamp) > ttl
    
    def touch(self) -> None:
        self.timestamp = time.time()
        self.hit_count += 1


class FlowCache:
    """
    Flow cache for fast-path packet processing.
    Caches decisions for established flows to avoid rule matching.
    """
    
    def __init__(self, max_size: int = 100000, ttl: int = 60):
        self.max_size = max_size
        self.ttl = ttl
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.lock = threading.RLock()
        self.hits = 0
        self.misses = 0
        self.evictions = 0
    
    def get(self, flow_key: str) -> Optional[CacheEntry]:
        with self.lock:
            if flow_key in self.cache:
                entry = self.cache[flow_key]
                if not entry.is_expired(self.ttl):
                    self.cache.move_to_end(flow_key)
                    entry.touch()
                    self.hits += 1
                    return entry
                else:
                    del self.cache[flow_key]
            self.misses += 1
            return None
    
    def put(self, flow_key: str, action: CachedAction, rule_id: Optional[int] = None, nat_mapping: Optional[Dict] = None) -> None:
        with self.lock:
            if flow_key in self.cache:
                self.cache.move_to_end(flow_key)
            else:
                while len(self.cache) >= self.max_size:
                    self.cache.popitem(last=False)
                    self.evictions += 1
            
            self.cache[flow_key] = CacheEntry(action=action, rule_id=rule_id, nat_mapping=nat_mapping)
    
    def invalidate(self, flow_key: str) -> bool:
        with self.lock:
            if flow_key in self.cache:
                del self.cache[flow_key]
                return True
            return False
    
    def clear(self) -> None:
        with self.lock:
            self.cache.clear()
    
    def cleanup_expired(self) -> int:
        current_time = time.time()
        expired = []
        with self.lock:
            for key, entry in self.cache.items():
                if (current_time - entry.timestamp) > self.ttl:
                    expired.append(key)
            for key in expired:
                del self.cache[key]
        return len(expired)
    
    def get_stats(self) -> dict:
        with self.lock:
            total = self.hits + self.misses
            return {
                "size": len(self.cache),
                "max_size": self.max_size,
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": round(self.hits / total * 100, 2) if total > 0 else 0,
                "evictions": self.evictions,
            }


class BidirectionalFlowCache:
    """Cache that tracks both directions of a flow."""
    
    def __init__(self, max_size: int = 100000, ttl: int = 60):
        self.forward = FlowCache(max_size=max_size, ttl=ttl)
        self.reverse = FlowCache(max_size=max_size, ttl=ttl)
    
    def get(self, flow_key: str) -> Optional[CacheEntry]:
        entry = self.forward.get(flow_key)
        if entry:
            return entry
        return self.reverse.get(flow_key)
    
    def put_bidirectional(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: int, action: CachedAction, **kwargs) -> None:
        forward_key = f"{protocol}:{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        reverse_key = f"{protocol}:{dst_ip}:{dst_port}-{src_ip}:{src_port}"
        self.forward.put(forward_key, action, **kwargs)
        self.reverse.put(reverse_key, action, **kwargs)
    
    def invalidate_bidirectional(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: int) -> None:
        forward_key = f"{protocol}:{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        reverse_key = f"{protocol}:{dst_ip}:{dst_port}-{src_ip}:{src_port}"
        self.forward.invalidate(forward_key)
        self.reverse.invalidate(reverse_key)
    
    def get_stats(self) -> dict:
        return {"forward": self.forward.get_stats(), "reverse": self.reverse.get_stats()}


# =============================================================================
# IP Set
# =============================================================================

@dataclass
class IPRange:
    network: IPv4Network
    start_int: int
    end_int: int
    metadata: Optional[Dict[str, Any]] = None
    
    @classmethod
    def from_cidr(cls, cidr: str, metadata: Optional[Dict] = None) -> 'IPRange':
        network = ip_network(cidr, strict=False)
        hosts = list(network.hosts()) if network.prefixlen < 32 else [network.network_address]
        start = int(network.network_address)
        end = int(network.broadcast_address)
        return cls(network=network, start_int=start, end_int=end, metadata=metadata)


class CIDRTree:
    """Efficient CIDR lookup using prefix length sorting."""
    
    def __init__(self):
        self.ranges: List[IPRange] = []
        self._sorted = False
        self.lock = threading.RLock()
    
    def add(self, cidr: str, metadata: Optional[Dict] = None) -> None:
        with self.lock:
            ip_range = IPRange.from_cidr(cidr, metadata)
            self.ranges.append(ip_range)
            self._sorted = False
    
    def _ensure_sorted(self) -> None:
        if not self._sorted:
            self.ranges.sort(key=lambda r: -r.network.prefixlen)
            self._sorted = True
    
    def find_match(self, ip: str) -> Optional[IPRange]:
        with self.lock:
            self._ensure_sorted()
            try:
                addr = ip_address(ip)
                addr_int = int(addr)
                for ip_range in self.ranges:
                    if ip_range.start_int <= addr_int <= ip_range.end_int:
                        return ip_range
            except ValueError:
                pass
            return None
    
    def contains(self, ip: str) -> bool:
        return self.find_match(ip) is not None
    
    def remove(self, cidr: str) -> bool:
        with self.lock:
            network = ip_network(cidr, strict=False)
            for i, r in enumerate(self.ranges):
                if r.network == network:
                    self.ranges.pop(i)
                    return True
            return False
    
    def clear(self) -> None:
        with self.lock:
            self.ranges.clear()
    
    def __len__(self) -> int:
        return len(self.ranges)


class IPSet:
    """
    High-performance IP set for efficient matching.
    Combines exact IP lookup (O(1)) and CIDR matching (O(log n)).
    """
    
    def __init__(self):
        self.exact_ips: Dict[str, Optional[Dict]] = {}
        self.cidr_tree = CIDRTree()
        self.lock = threading.RLock()
    
    def add(self, ip_or_cidr: str, metadata: Optional[Dict] = None) -> None:
        with self.lock:
            if '/' in ip_or_cidr:
                network = ip_network(ip_or_cidr, strict=False)
                if network.prefixlen == 32:
                    self.exact_ips[str(network.network_address)] = metadata
                else:
                    self.cidr_tree.add(ip_or_cidr, metadata)
            else:
                self.exact_ips[ip_or_cidr] = metadata
    
    def contains(self, ip: str) -> bool:
        with self.lock:
            if ip in self.exact_ips:
                return True
            return self.cidr_tree.contains(ip)
    
    def find_match(self, ip: str) -> Optional[IPRange]:
        with self.lock:
            if ip in self.exact_ips:
                return IPRange.from_cidr(f"{ip}/32", self.exact_ips[ip])
            return self.cidr_tree.find_match(ip)
    
    def remove(self, ip_or_cidr: str) -> bool:
        with self.lock:
            if '/' in ip_or_cidr:
                return self.cidr_tree.remove(ip_or_cidr)
            elif ip_or_cidr in self.exact_ips:
                del self.exact_ips[ip_or_cidr]
                return True
            return False
    
    def clear(self) -> None:
        with self.lock:
            self.exact_ips.clear()
            self.cidr_tree.clear()
    
    def __len__(self) -> int:
        return len(self.exact_ips) + len(self.cidr_tree)
    
    def get_stats(self) -> dict:
        return {"exact_ips": len(self.exact_ips), "cidr_ranges": len(self.cidr_tree)}


class WellKnownIPSets:
    """Pre-defined IP sets for common networks."""
    
    @staticmethod
    def private_networks() -> IPSet:
        ip_set = IPSet()
        for cidr in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]:
            ip_set.add(cidr, {"type": "private"})
        return ip_set
    
    @staticmethod
    def loopback() -> IPSet:
        ip_set = IPSet()
        ip_set.add("127.0.0.0/8", {"type": "loopback"})
        return ip_set
    
    @staticmethod
    def link_local() -> IPSet:
        ip_set = IPSet()
        ip_set.add("169.254.0.0/16", {"type": "link_local"})
        return ip_set
    
    @staticmethod
    def multicast() -> IPSet:
        ip_set = IPSet()
        ip_set.add("224.0.0.0/4", {"type": "multicast"})
        return ip_set
    
    @staticmethod
    def bogons() -> IPSet:
        """Non-routable/bogon addresses"""
        ip_set = IPSet()
        bogons = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"]
        for cidr in bogons:
            ip_set.add(cidr, {"type": "bogon"})
        return ip_set

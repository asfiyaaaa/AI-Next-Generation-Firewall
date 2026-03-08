"""
High-Performance Connection Table for Phase1

Design Goals:
- Track 2,000,000+ concurrent connections
- O(1) lookup and insert
- Minimal lock contention via sharding
- LRU eviction per shard
- Thread-safe operations
"""

import threading
import time
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Tuple, List
from collections import OrderedDict
from enum import Enum


logger = logging.getLogger(__name__)


class ConnectionState(Enum):
    """TCP/UDP connection states"""
    NEW = "NEW"
    SYN_SENT = "SYN_SENT"
    SYN_RECV = "SYN_RECV"
    ESTABLISHED = "ESTABLISHED"
    FIN_WAIT = "FIN_WAIT"
    CLOSE_WAIT = "CLOSE_WAIT"
    CLOSING = "CLOSING"
    TIME_WAIT = "TIME_WAIT"
    CLOSED = "CLOSED"
    INVALID = "INVALID"
    # UDP states
    UDP_NEW = "UDP_NEW"
    UDP_ESTABLISHED = "UDP_ESTABLISHED"
    # ICMP states
    ICMP_NEW = "ICMP_NEW"
    ICMP_ESTABLISHED = "ICMP_ESTABLISHED"


@dataclass
class Connection:
    """
    Represents a tracked network connection.
    Stores both connection metadata and statistics.
    """
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: int  # 6=TCP, 17=UDP, 1=ICMP
    state: ConnectionState
    created: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    
    # Traffic statistics
    bytes_in: int = 0
    bytes_out: int = 0
    packets_in: int = 0
    packets_out: int = 0
    
    # NAT tracking (if applicable)
    nat_src_ip: Optional[str] = None
    nat_src_port: Optional[int] = None
    nat_dst_ip: Optional[str] = None
    nat_dst_port: Optional[int] = None
    
    # Flags
    is_assured: bool = False  # Seen traffic in both directions
    mark: int = 0  # For rule matching/marking
    
    def get_key(self) -> str:
        """Generate unique connection key"""
        return f"{self.protocol}:{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}"
    
    def get_reverse_key(self) -> str:
        """Generate reverse direction key"""
        return f"{self.protocol}:{self.dst_ip}:{self.dst_port}-{self.src_ip}:{self.src_port}"
    
    def update_stats(self, bytes_count: int, is_inbound: bool) -> None:
        """Update traffic statistics"""
        if is_inbound:
            self.bytes_in += bytes_count
            self.packets_in += 1
        else:
            self.bytes_out += bytes_count
            self.packets_out += 1
        self.last_seen = time.time()
    
    def is_expired(self, timeout: int) -> bool:
        """Check if connection has expired"""
        return (time.time() - self.last_seen) > timeout
    
    def __repr__(self) -> str:
        return (f"Connection({self.src_ip}:{self.src_port} -> "
                f"{self.dst_ip}:{self.dst_port} [{self.state.value}])")


class ConnectionShard:
    """
    Single shard of the connection table.
    Uses OrderedDict for O(1) LRU eviction.
    Thread-safe with per-shard locking.
    """
    
    def __init__(self, max_size: int = 10000, timeout: int = 300):
        self.connections: OrderedDict[str, Connection] = OrderedDict()
        self.reverse_index: Dict[str, str] = {}  # reverse_key -> forward_key
        self.max_size = max_size
        self.timeout = timeout
        self.lock = threading.RLock()
        
        # Statistics
        self.hits = 0
        self.misses = 0
        self.evictions = 0
    
    def get(self, key: str) -> Optional[Connection]:
        """
        Lookup connection by key.
        Moves to end of OrderedDict (most recently used).
        """
        with self.lock:
            if key in self.connections:
                self.connections.move_to_end(key)
                self.hits += 1
                return self.connections[key]
            self.misses += 1
            return None
    
    def get_by_reverse(self, reverse_key: str) -> Optional[Connection]:
        """Lookup connection by reverse key (for response packets)"""
        with self.lock:
            if reverse_key in self.reverse_index:
                forward_key = self.reverse_index[reverse_key]
                return self.get(forward_key)
            return None
    
    def put(self, conn: Connection) -> bool:
        """
        Insert or update connection.
        Returns True if new connection, False if update.
        """
        key = conn.get_key()
        reverse_key = conn.get_reverse_key()
        
        with self.lock:
            is_new = key not in self.connections
            
            if is_new:
                # Check capacity and evict if needed
                while len(self.connections) >= self.max_size:
                    self._evict_one()
            else:
                # Move existing to end
                self.connections.move_to_end(key)
            
            self.connections[key] = conn
            self.reverse_index[reverse_key] = key
            
            return is_new
    
    def delete(self, key: str) -> bool:
        """Delete connection by key"""
        with self.lock:
            if key in self.connections:
                conn = self.connections[key]
                reverse_key = conn.get_reverse_key()
                
                del self.connections[key]
                if reverse_key in self.reverse_index:
                    del self.reverse_index[reverse_key]
                return True
            return False
    
    def _evict_one(self) -> None:
        """Evict oldest (least recently used) connection"""
        if self.connections:
            key, conn = self.connections.popitem(last=False)
            reverse_key = conn.get_reverse_key()
            if reverse_key in self.reverse_index:
                del self.reverse_index[reverse_key]
            self.evictions += 1
    
    def cleanup_expired(self) -> int:
        """Remove all expired connections"""
        expired_keys = []
        current_time = time.time()
        
        with self.lock:
            for key, conn in self.connections.items():
                if (current_time - conn.last_seen) > self.timeout:
                    expired_keys.append(key)
            
            for key in expired_keys:
                self.delete(key)
        
        return len(expired_keys)
    
    def get_stats(self) -> Dict:
        """Get shard statistics"""
        with self.lock:
            return {
                "connections": len(self.connections),
                "hits": self.hits,
                "misses": self.misses,
                "evictions": self.evictions,
                "hit_rate": self.hits / (self.hits + self.misses) if (self.hits + self.misses) > 0 else 0
            }


class ConnectionTable:
    """
    Sharded connection table for high-scale tracking.
    
    Design:
    - 256 shards to reduce lock contention
    - Each shard has independent LRU eviction
    - O(1) lookup and insert via hashing
    - Supports 2M+ concurrent connections
    
    Usage:
        table = ConnectionTable(max_connections=2_000_000)
        
        # Create new connection
        conn = Connection(
            src_ip="192.168.1.100",
            src_port=54321,
            dst_ip="10.0.0.1",
            dst_port=80,
            protocol=6,
            state=ConnectionState.NEW
        )
        table.put(conn)
        
        # Lookup
        found = table.get("192.168.1.100", 54321, "10.0.0.1", 80, 6)
    """
    
    def __init__(
        self,
        max_connections: int = 2_000_000,
        num_shards: int = 256,
        timeout: int = 300
    ):
        self.num_shards = num_shards
        self.timeout = timeout
        shard_size = max_connections // num_shards
        
        self.shards: List[ConnectionShard] = [
            ConnectionShard(max_size=shard_size, timeout=timeout)
            for _ in range(num_shards)
        ]
        
        # Background cleanup thread
        self._cleanup_thread: Optional[threading.Thread] = None
        self._running = False
    
    def _hash_key(self, key: str) -> int:
        """Fast hash for shard selection"""
        # Use Python's built-in hash, masked to shard count
        return hash(key) % self.num_shards
    
    def _make_key(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: int
    ) -> str:
        """Generate connection key from 5-tuple"""
        return f"{protocol}:{src_ip}:{src_port}-{dst_ip}:{dst_port}"
    
    def _get_shard(self, key: str) -> ConnectionShard:
        """Get appropriate shard for key"""
        return self.shards[self._hash_key(key)]
    
    def get(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: int
    ) -> Optional[Connection]:
        """
        Lookup connection by 5-tuple.
        Returns None if not found.
        """
        key = self._make_key(src_ip, src_port, dst_ip, dst_port, protocol)
        return self._get_shard(key).get(key)
    
    def get_reverse(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: int
    ) -> Optional[Connection]:
        """
        Lookup connection by reverse 5-tuple (for response packets).
        Checks if a connection exists in the opposite direction.
        """
        reverse_key = self._make_key(dst_ip, dst_port, src_ip, src_port, protocol)
        # The reverse key of this packet would be the forward key of the original connection
        forward_key = self._make_key(src_ip, src_port, dst_ip, dst_port, protocol)
        return self._get_shard(reverse_key).get_by_reverse(forward_key)
    
    def put(self, conn: Connection) -> bool:
        """
        Insert or update connection.
        Returns True if new, False if update.
        """
        key = conn.get_key()
        return self._get_shard(key).put(conn)
    
    def delete(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: int
    ) -> bool:
        """Delete connection by 5-tuple"""
        key = self._make_key(src_ip, src_port, dst_ip, dst_port, protocol)
        return self._get_shard(key).delete(key)
    
    def update_state(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: int,
        new_state: ConnectionState
    ) -> bool:
        """Update connection state"""
        conn = self.get(src_ip, src_port, dst_ip, dst_port, protocol)
        if conn:
            conn.state = new_state
            conn.last_seen = time.time()
            return True
        return False
    
    def cleanup_all(self) -> int:
        """Clean up expired connections in all shards"""
        total_cleaned = 0
        for shard in self.shards:
            total_cleaned += shard.cleanup_expired()
        return total_cleaned
    
    def start_cleanup_thread(self, interval: int = 30) -> None:
        """Start background cleanup thread"""
        if self._running:
            return
        
        self._running = True
        
        def cleanup_loop():
            while self._running:
                time.sleep(interval)
                cleaned = self.cleanup_all()
                if cleaned > 0:
                    logger.debug(f"Cleaned {cleaned} expired connections")
        
        self._cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        self._cleanup_thread.start()
    
    def stop_cleanup_thread(self) -> None:
        """Stop background cleanup thread"""
        self._running = False
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=5)
    
    def get_stats(self) -> Dict:
        """Get table-wide statistics"""
        total_connections = 0
        total_hits = 0
        total_misses = 0
        total_evictions = 0
        
        state_counts: Dict[str, int] = {}
        
        for shard in self.shards:
            stats = shard.get_stats()
            total_connections += stats["connections"]
            total_hits += stats["hits"]
            total_misses += stats["misses"]
            total_evictions += stats["evictions"]
            
            with shard.lock:
                for conn in shard.connections.values():
                    state = conn.state.value
                    state_counts[state] = state_counts.get(state, 0) + 1
        
        return {
            "total_connections": total_connections,
            "max_connections": sum(s.max_size for s in self.shards),
            "num_shards": self.num_shards,
            "avg_per_shard": total_connections // self.num_shards if self.num_shards > 0 else 0,
            "total_hits": total_hits,
            "total_misses": total_misses,
            "total_evictions": total_evictions,
            "hit_rate": total_hits / (total_hits + total_misses) if (total_hits + total_misses) > 0 else 0,
            "state_distribution": state_counts
        }
    
    def __len__(self) -> int:
        """Return total number of tracked connections"""
        return sum(len(s.connections) for s in self.shards)
    
    def __repr__(self) -> str:
        return f"ConnectionTable(connections={len(self)}, shards={self.num_shards})"

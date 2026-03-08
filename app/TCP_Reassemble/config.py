"""
TCP Stream Reassembly Configuration (Suricata-Inspired)

Tunable parameters for high-performance stream reassembly.
Designed for 1M+ concurrent connections with memory bounds.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class OverlapPolicy(Enum):
    """
    Overlap resolution policies for TCP segment overlaps.
    Different OS stacks handle overlaps differently - attackers exploit this for evasion.
    
    BSD: Favor old data (first segment wins)
    LINUX: Favor new data (last segment wins) 
    WINDOWS: Favor old data for some cases, new for others
    FIRST: Always favor first received segment
    LAST: Always favor last received segment
    """
    BSD = "bsd"
    LINUX = "linux"
    WINDOWS = "windows"
    FIRST = "first"
    LAST = "last"


class StreamPolicy(Enum):
    """Stream handling policies."""
    STRICT = "strict"      # Drop invalid sequences
    PERMISSIVE = "permissive"  # Accept and log anomalies
    INLINE = "inline"      # IPS mode - can modify/block


@dataclass
class StreamConfig:
    """
    TCP Stream Reassembly Configuration.
    
    Modeled after Suricata's stream engine tunables for enterprise deployments.
    Supports 1M+ concurrent connections with careful memory management.
    """
    
    # === Connection Limits ===
    max_streams: int = 1_000_000
    """Maximum concurrent TCP streams to track"""
    
    max_streams_per_host: int = 10_000
    """Per-host stream limit (anti-DoS)"""
    
    # === Memory Limits ===
    stream_memcap: int = 256 * 1024 * 1024  # 256MB
    """Global memory cap for all streams"""
    
    reassembly_memcap: int = 128 * 1024 * 1024  # 128MB
    """Memory cap for reassembly buffers specifically"""
    
    reassembly_depth: int = 1_000_000  # 1MB
    """Maximum bytes to reassemble per stream direction"""
    
    # === Timeouts (seconds) ===
    stream_timeout: int = 300
    """Idle timeout before stream cleanup"""
    
    stream_established_timeout: int = 3600
    """Timeout for established connections (1 hour)"""
    
    stream_closed_timeout: int = 60
    """Time to keep closed streams (for late packets)"""
    
    emergency_recovery_timeout: int = 30
    """Aggressive timeout when approaching memcap"""
    
    # === Segment Handling ===
    overlap_policy: OverlapPolicy = OverlapPolicy.BSD
    """How to resolve overlapping segments"""
    
    checksum_validation: bool = True
    """Validate TCP checksums (disable for performance)"""
    
    async_oneside: bool = True
    """Track streams even when only one direction seen"""
    
    midstream: bool = True
    """Pick up established streams mid-flow"""
    
    # === Security Settings ===
    detect_evasion: bool = True
    """Flag potential evasion techniques"""
    
    max_synack_queued: int = 5
    """Max SYN-ACKs before declaring attack"""
    
    prealloc_sessions: int = 10_000
    """Preallocate session slots for performance"""
    
    # === Output/Callback ===
    flush_on_fin: bool = True
    """Flush stream data when FIN received"""
    
    flush_on_rst: bool = False
    """Flush stream data when RST received (usually not)"""
    
    min_flush_depth: int = 1024
    """Minimum bytes before flushing to Phase 3"""
    
    # === Stream Policy ===
    policy: StreamPolicy = StreamPolicy.PERMISSIVE
    """How strictly to enforce TCP state machine"""
    
    def validate(self) -> bool:
        """Validate configuration parameters."""
        errors = []
        
        if self.max_streams <= 0:
            errors.append("max_streams must be positive")
        if self.stream_memcap < 1024 * 1024:
            errors.append("stream_memcap should be at least 1MB")
        if self.reassembly_depth < 1024:
            errors.append("reassembly_depth should be at least 1KB")
        if self.stream_timeout <= 0:
            errors.append("stream_timeout must be positive")
            
        if errors:
            for err in errors:
                logger.error(f"StreamConfig validation error: {err}")
            return False
        return True
    
    def estimate_memory_usage(self) -> int:
        """
        Estimate maximum memory usage in bytes.
        
        Formula: 
        - Stream metadata: ~500 bytes per stream
        - Reassembly buffers: reassembly_depth * 2 (bidirectional) per active stream
        - Assume 10% of streams have active buffers
        """
        metadata = self.max_streams * 500
        active_buffers = int(self.max_streams * 0.1) * self.reassembly_depth * 2
        return min(metadata + active_buffers, self.stream_memcap + self.reassembly_memcap)


def get_default_config() -> StreamConfig:
    """Get default production configuration."""
    return StreamConfig()


def get_low_memory_config() -> StreamConfig:
    """Configuration for memory-constrained environments."""
    return StreamConfig(
        max_streams=100_000,
        stream_memcap=64 * 1024 * 1024,  # 64MB
        reassembly_memcap=32 * 1024 * 1024,  # 32MB
        reassembly_depth=65535,  # 64KB
        prealloc_sessions=1_000
    )


def get_high_security_config() -> StreamConfig:
    """Configuration with maximum security checks."""
    return StreamConfig(
        overlap_policy=OverlapPolicy.FIRST,  # Deterministic
        checksum_validation=True,
        detect_evasion=True,
        policy=StreamPolicy.STRICT,
        midstream=False,  # Don't pick up mid-flow
        flush_on_rst=False
    )

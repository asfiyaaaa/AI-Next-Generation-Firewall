"""
Phase 3 Callback Interface

Defines the data structures and callback signature for
forwarding reassembled TCP streams to Phase 3 processing.
"""
import time
import logging
from dataclasses import dataclass, field
from typing import Dict, Any, Callable, Optional, List
from enum import Enum

logger = logging.getLogger(__name__)


class FlushReason(Enum):
    """Why the stream data was flushed."""
    DATA_READY = "data_ready"       # Contiguous data available
    DEPTH_LIMIT = "depth_limit"     # Reached reassembly depth
    FIN_RECEIVED = "fin_received"   # TCP FIN flag
    RST_RECEIVED = "rst_received"   # TCP RST flag
    TIMEOUT = "timeout"             # Stream timeout
    MEMORY_PRESSURE = "memory"      # Memory limit reached
    FORCED = "forced"               # Manual/API flush


@dataclass
class ReassembledStream:
    """
    Represents a chunk of reassembled TCP stream data ready for Phase 3.
    
    This is the output interface from the reassembly engine to Phase 3.
    Contains both the data and metadata about the stream.
    """
    # === Stream Identification ===
    stream_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    
    # === Data ===
    data: bytes
    direction: str  # "c2s" (client to server) or "s2c" (server to client)
    
    # === Sequence Info ===
    seq_start: int = 0              # Starting sequence number of this chunk
    seq_end: int = 0                # Ending sequence number
    
    # === Status ===
    is_complete: bool = False       # Stream finished (FIN/RST/timeout)?
    has_gaps: bool = False          # Any gaps in this data?
    flush_reason: FlushReason = FlushReason.DATA_READY
    
    # === Metadata ===
    timestamp: float = field(default_factory=time.time)
    chunk_index: int = 0            # Which chunk of this stream (0-indexed)
    
    # DPI and app identification results
    app_protocol: Optional[str] = None
    dpi_verdict: Optional[Dict[str, Any]] = None
    
    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def data_length(self) -> int:
        """Length of reassembled data."""
        return len(self.data)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization/logging."""
        return {
            "stream_id": self.stream_id,
            "src": f"{self.src_ip}:{self.src_port}",
            "dst": f"{self.dst_ip}:{self.dst_port}",
            "direction": self.direction,
            "data_length": len(self.data),
            "seq_range": f"{self.seq_start}-{self.seq_end}",
            "is_complete": self.is_complete,
            "has_gaps": self.has_gaps,
            "flush_reason": self.flush_reason.value,
            "chunk_index": self.chunk_index,
            "app_protocol": self.app_protocol,
            "timestamp": self.timestamp
        }


# Type alias for Phase 3 callback function
Phase3Callback = Callable[[ReassembledStream], None]


class Phase3CallbackHandler:
    """
    Manages callbacks to Phase 3 processing.
    
    Provides:
    - Callback registration
    - Error handling for callback failures
    - Statistics tracking
    - Optional buffering/batching
    """
    
    def __init__(self):
        self._callbacks: List[Phase3Callback] = []
        self._stats = {
            "streams_sent": 0,
            "bytes_sent": 0,
            "callback_errors": 0,
            "last_error": None
        }
    
    def register(self, callback: Phase3Callback) -> None:
        """Register a Phase 3 callback function."""
        if callback not in self._callbacks:
            self._callbacks.append(callback)
            logger.info(f"Registered Phase 3 callback: {callback.__name__ if hasattr(callback, '__name__') else 'anonymous'}")
    
    def unregister(self, callback: Phase3Callback) -> bool:
        """Unregister a callback. Returns True if found and removed."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)
            return True
        return False
    
    def send(self, stream: ReassembledStream) -> bool:
        """
        Send reassembled stream to all registered callbacks.
        
        Returns True if at least one callback succeeded.
        """
        if not self._callbacks:
            # No callbacks registered - log for debugging
            logger.debug(f"[REASSEMBLY] No Phase 3 callbacks. Stream {stream.stream_id}: {len(stream.data)} bytes")
            return False
        
        success = False
        for callback in self._callbacks:
            try:
                callback(stream)
                success = True
            except Exception as e:
                self._stats["callback_errors"] += 1
                self._stats["last_error"] = str(e)
                logger.error(f"Phase 3 callback error: {e}")
        
        if success:
            self._stats["streams_sent"] += 1
            self._stats["bytes_sent"] += len(stream.data)
        
        return success
    
    @property
    def has_callbacks(self) -> bool:
        """Check if any callbacks are registered."""
        return len(self._callbacks) > 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Get callback statistics."""
        return dict(self._stats)


# === Default Callbacks for Testing ===

def log_callback(stream: ReassembledStream) -> None:
    """
    Default callback that logs reassembled streams.
    
    Useful for debugging and testing when Phase 3 is not yet integrated.
    """
    logger.info(
        f"[REASSEMBLY -> PHASE3] "
        f"Stream: {stream.stream_id} | "
        f"Dir: {stream.direction} | "
        f"Size: {len(stream.data)} bytes | "
        f"Seq: {stream.seq_start}-{stream.seq_end} | "
        f"Complete: {stream.is_complete} | "
        f"Reason: {stream.flush_reason.value}"
    )
    
    # Log first 100 bytes of data for debugging
    if stream.data and logger.isEnabledFor(logging.DEBUG):
        preview = stream.data[:100]
        try:
            preview_str = preview.decode('utf-8', errors='replace')
        except:
            preview_str = preview.hex()
        logger.debug(f"[REASSEMBLY DATA] {preview_str}...")


def null_callback(stream: ReassembledStream) -> None:
    """
    Callback that does nothing.
    
    Used when Phase 3 processing is disabled or for benchmarking.
    """
    pass


# Placeholder for future Phase 3 integrations
class Phase3Integration:
    """
    Base class for Phase 3 integration implementations.
    
    Subclass this to create specific integrations:
    - IPC-based (shared memory, pipes)
    - Queue-based (multiprocessing.Queue)
    - Network-based (HTTP, gRPC)
    """
    
    def __init__(self, name: str = "Phase3"):
        self.name = name
        self.enabled = True
    
    def process(self, stream: ReassembledStream) -> bool:
        """Process a reassembled stream. Override in subclass."""
        raise NotImplementedError
    
    def __call__(self, stream: ReassembledStream) -> None:
        """Make instance callable as a callback."""
        if self.enabled:
            self.process(stream)

   
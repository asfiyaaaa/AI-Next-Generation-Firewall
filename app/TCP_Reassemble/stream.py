"""
TCP Stream State Machine (Suricata-Inspired)

Implements RFC 793 TCP state machine with extensions for:
- Bidirectional stream tracking
- Sequence number validation
- Window tracking
- Evasion detection
"""
import time
import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Dict, Any, Tuple

logger = logging.getLogger(__name__)


class StreamState(Enum):
    """
    TCP Stream States (RFC 793 + Extensions)
    
    Standard TCP states plus additional states for tracking
    mid-stream pickups and invalid sequences.
    """
    # === Pre-connection ===
    NONE = auto()          # Stream allocated but not seen
    NEW = auto()           # First packet seen (any direction)
    
    # === Connection Establishment ===
    SYN_SENT = auto()      # SYN sent, waiting SYN-ACK
    SYN_RECV = auto()      # SYN-ACK sent, waiting ACK
    
    # === Established ===
    ESTABLISHED = auto()   # 3-way handshake complete
    
    # === Connection Termination ===
    FIN_WAIT1 = auto()     # FIN sent
    FIN_WAIT2 = auto()     # FIN acked, waiting peer FIN
    CLOSING = auto()       # Both sides sent FIN
    TIME_WAIT = auto()     # Waiting for late packets
    CLOSE_WAIT = auto()    # Received FIN, waiting app close
    LAST_ACK = auto()      # Sent FIN after CLOSE_WAIT
    CLOSED = auto()        # Connection terminated
    
    # === Special States ===
    MIDSTREAM = auto()     # Picked up mid-flow (no SYN)
    RST = auto()           # Reset received
    INVALID = auto()       # Invalid state transition detected


class Direction(Enum):
    """Packet direction relative to stream initiator."""
    TO_SERVER = "c2s"      # Client to Server
    TO_CLIENT = "s2c"      # Server to Client


@dataclass
class SequenceTracker:
    """
    Tracks TCP sequence numbers for one direction.
    
    Handles wrap-around (sequence numbers are 32-bit unsigned).
    """
    isn: int = 0                    # Initial Sequence Number
    next_seq: int = 0               # Next expected sequence number
    last_ack: int = 0               # Last ACK sent
    window: int = 65535             # Receive window
    window_scale: int = 0           # Window scale factor (from SYN options)
    
    # Statistics
    bytes_seen: int = 0
    segments_seen: int = 0
    retransmissions: int = 0
    out_of_order: int = 0
    gaps: int = 0
    overlaps: int = 0
    
    def update(self, seq: int, payload_len: int, ack: int = 0, win: int = 0):
        """Update sequence tracking with new segment."""
        self.segments_seen += 1
        self.bytes_seen += payload_len
        
        if ack > 0:
            self.last_ack = ack
        if win > 0:
            self.window = win << self.window_scale
        
        # Expected sequence calculation
        expected = self.next_seq
        end_seq = seq + payload_len
        
        if payload_len > 0:
            # Check for out-of-order
            if self._seq_lt(seq, expected):
                # Retransmission or overlap
                if self._seq_le(end_seq, expected):
                    self.retransmissions += 1
                else:
                    self.overlaps += 1
            elif self._seq_gt(seq, expected):
                # Gap detected
                self.gaps += 1
                self.out_of_order += 1
            
            # Update next expected
            if self._seq_gt(end_seq, self.next_seq):
                self.next_seq = end_seq
    
    @staticmethod
    def _seq_lt(a: int, b: int) -> bool:
        """Sequence number less-than with wrap handling."""
        return ((a - b) & 0xFFFFFFFF) > 0x80000000
    
    @staticmethod
    def _seq_le(a: int, b: int) -> bool:
        """Sequence number less-than-or-equal."""
        return a == b or SequenceTracker._seq_lt(a, b)
    
    @staticmethod
    def _seq_gt(a: int, b: int) -> bool:
        """Sequence number greater-than."""
        return SequenceTracker._seq_lt(b, a)


@dataclass
class TCPStream:
    """
    Represents a tracked TCP connection.
    
    Bidirectional: tracks both client→server and server→client.
    """
    # === Identification (5-tuple) ===
    stream_id: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 6  # TCP
    
    # === State ===
    state: StreamState = StreamState.NONE
    prev_state: StreamState = StreamState.NONE
    
    # === Sequence Tracking (bidirectional) ===
    client_seq: SequenceTracker = field(default_factory=SequenceTracker)
    server_seq: SequenceTracker = field(default_factory=SequenceTracker)
    
    # === Timestamps ===
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    established_at: float = 0.0
    closed_at: float = 0.0
    
    # === Flags ===
    midstream_pickup: bool = False     # Started tracking mid-flow
    has_gaps: bool = False             # Data gaps detected
    evasion_flags: int = 0             # Bitmap of detected evasion attempts
    
    # === Associated Data ===
    app_protocol: Optional[str] = None     # Detected application (HTTP, TLS, etc.)
    dpi_verdict: Optional[Dict] = None     # Last DPI verdict
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Generate stream ID if not set."""
        if not self.stream_id:
            self.stream_id = f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}"
    
    def get_reverse_id(self) -> str:
        """Get stream ID for reverse direction (response packets)."""
        return f"{self.dst_ip}:{self.dst_port}-{self.src_ip}:{self.src_port}"
    
    def update_state(self, new_state: StreamState) -> None:
        """Update stream state with logging."""
        if new_state != self.state:
            self.prev_state = self.state
            self.state = new_state
            self.last_seen = time.time()
            
            if new_state == StreamState.ESTABLISHED and self.established_at == 0:
                self.established_at = time.time()
            elif new_state in (StreamState.CLOSED, StreamState.RST, StreamState.TIME_WAIT):
                self.closed_at = time.time()
    
    def process_flags(self, syn: bool, ack: bool, fin: bool, rst: bool, 
                      direction: Direction) -> StreamState:
        """
        Process TCP flags and return new state.
        
        Implements RFC 793 state machine with practical relaxations.
        """
        current = self.state
        
        # RST always resets
        if rst:
            return StreamState.RST
        
        # State transitions
        if current == StreamState.NONE:
            if syn and not ack:
                return StreamState.SYN_SENT
            else:
                # Mid-stream pickup
                self.midstream_pickup = True
                return StreamState.MIDSTREAM
                
        elif current == StreamState.SYN_SENT:
            if syn and ack:
                return StreamState.SYN_RECV
            elif ack:
                # Unusual but handle it
                return StreamState.ESTABLISHED
                
        elif current == StreamState.SYN_RECV:
            if ack:
                return StreamState.ESTABLISHED
                
        elif current == StreamState.ESTABLISHED:
            if fin:
                return StreamState.FIN_WAIT1
                
        elif current == StreamState.FIN_WAIT1:
            if fin and ack:
                return StreamState.CLOSING
            elif ack:
                return StreamState.FIN_WAIT2
            elif fin:
                return StreamState.CLOSING
                
        elif current == StreamState.FIN_WAIT2:
            if fin:
                return StreamState.TIME_WAIT
                
        elif current == StreamState.CLOSING:
            if ack:
                return StreamState.TIME_WAIT
                
        elif current == StreamState.CLOSE_WAIT:
            if fin:
                return StreamState.LAST_ACK
                
        elif current == StreamState.LAST_ACK:
            if ack:
                return StreamState.CLOSED
                
        elif current == StreamState.MIDSTREAM:
            # Stay in midstream until explicit termination
            if fin:
                return StreamState.FIN_WAIT1
        
        return current  # No change
    
    def is_established(self) -> bool:
        """Check if stream is in data-transfer state."""
        return self.state in (StreamState.ESTABLISHED, StreamState.MIDSTREAM)
    
    def is_closed(self) -> bool:
        """Check if stream is terminated."""
        return self.state in (StreamState.CLOSED, StreamState.RST, 
                              StreamState.TIME_WAIT, StreamState.INVALID)
    
    def get_direction(self, src_ip: str, src_port: int) -> Direction:
        """Determine packet direction based on source."""
        if src_ip == self.src_ip and src_port == self.src_port:
            return Direction.TO_SERVER
        return Direction.TO_CLIENT
    
    def get_stats(self) -> Dict[str, Any]:
        """Get stream statistics."""
        return {
            "stream_id": self.stream_id,
            "state": self.state.name,
            "duration": time.time() - self.created_at,
            "client_bytes": self.client_seq.bytes_seen,
            "server_bytes": self.server_seq.bytes_seen,
            "client_segments": self.client_seq.segments_seen,
            "server_segments": self.server_seq.segments_seen,
            "retransmissions": self.client_seq.retransmissions + self.server_seq.retransmissions,
            "out_of_order": self.client_seq.out_of_order + self.server_seq.out_of_order,
            "gaps": self.client_seq.gaps + self.server_seq.gaps,
            "overlaps": self.client_seq.overlaps + self.server_seq.overlaps,
            "midstream": self.midstream_pickup,
            "app_protocol": self.app_protocol
        }


# === Evasion Detection Flags ===
class EvasionFlag:
    """Bitmap flags for detected evasion attempts."""
    NONE = 0
    TTL_MANIPULATION = 1 << 0          # TTL changes within stream
    OVERLAP_DIFFERENT_DATA = 1 << 1    # Overlapping segments with different content
    URGENT_DATA = 1 << 2               # Urgent pointer used (rare, often attack)
    WINDOW_ZERO = 1 << 3               # Zero window attacks
    SYN_WITH_DATA = 1 << 4             # SYN packet contains data
    TIMESTAMP_JUMP = 1 << 5            # Large timestamp jump
    CHECKSUM_INVALID = 1 << 6          # Bad checksum (but packet delivered)

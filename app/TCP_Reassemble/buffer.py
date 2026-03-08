"""
TCP Segment Buffer (Suricata-Inspired)

High-performance segment storage with:
- Gap detection and tracking
- Overlap resolution (configurable policy)
- Memory-bounded operation
- Efficient in-order delivery
"""
import logging
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Iterator
from bisect import insort_left, bisect_left
import copy

from .config import OverlapPolicy

logger = logging.getLogger(__name__)


@dataclass(order=True)
class Segment:
    """
    Represents a TCP segment in the reassembly buffer.
    
    Ordered by sequence number for efficient insertion.
    """
    seq: int              # Starting sequence number
    data: bytes = field(compare=False)
    end_seq: int = field(init=False, compare=False)
    
    # Metadata (for debugging/analysis)
    timestamp: float = field(default=0.0, compare=False)
    is_retransmit: bool = field(default=False, compare=False)
    
    def __post_init__(self):
        self.end_seq = self.seq + len(self.data)
    
    def __len__(self) -> int:
        return len(self.data)


@dataclass
class Gap:
    """Represents a gap in the segment buffer."""
    start_seq: int
    end_seq: int
    
    @property
    def size(self) -> int:
        return self.end_seq - self.start_seq


class SegmentBuffer:
    """
    Ordered segment buffer for one direction of a TCP stream.
    
    Features:
    - Maintains segments in sequence-number order
    - Detects and tracks gaps
    - Resolves overlaps according to policy
    - Delivers in-order data when available
    - Memory-bounded operation
    """
    
    def __init__(
        self,
        isn: int = 0,
        max_depth: int = 1_000_000,
        max_segments: int = 1000,
        overlap_policy: OverlapPolicy = OverlapPolicy.BSD
    ):
        self.isn = isn                      # Initial Sequence Number
        self.next_seq = isn                 # Next sequence expected for in-order delivery
        self.max_depth = max_depth          # Maximum bytes to buffer
        self.max_segments = max_segments    # Maximum segments to buffer
        self.overlap_policy = overlap_policy
        
        # Storage
        self._segments: List[Segment] = []
        self._current_depth: int = 0        # Total bytes buffered
        
        # Statistics
        self.stats = {
            "segments_received": 0,
            "bytes_received": 0,
            "segments_delivered": 0,
            "bytes_delivered": 0,
            "gaps_detected": 0,
            "overlaps_resolved": 0,
            "retransmissions": 0,
            "drops_depth": 0,       # Dropped due to depth limit
            "drops_segments": 0,    # Dropped due to segment limit
        }
    
    def insert(self, seq: int, data: bytes, timestamp: float = 0.0) -> bool:
        """
        Insert a segment into the buffer.
        
        Returns:
            True if segment was inserted/merged successfully
            False if segment was dropped (limits exceeded)
        """
        if not data:
            return False
        
        self.stats["segments_received"] += 1
        self.stats["bytes_received"] += len(data)
        
        # Check depth limit
        if self._current_depth + len(data) > self.max_depth:
            self.stats["drops_depth"] += 1
            logger.debug(f"Segment dropped: depth limit ({self._current_depth}/{self.max_depth})")
            return False
        
        # Check segment limit
        if len(self._segments) >= self.max_segments:
            self.stats["drops_segments"] += 1
            logger.debug(f"Segment dropped: segment limit ({len(self._segments)}/{self.max_segments})")
            return False
        
        segment = Segment(seq=seq, data=data, timestamp=timestamp)
        
        # Check for pure retransmission (entirely covered by next_seq)
        if segment.end_seq <= self.next_seq:
            self.stats["retransmissions"] += 1
            segment.is_retransmit = True
            # Still might need to keep for overlap resolution in some policies
            if self.overlap_policy in (OverlapPolicy.BSD, OverlapPolicy.FIRST):
                return True  # Silently accept but don't store
        
        # Handle overlaps with existing segments
        segment = self._resolve_overlaps(segment)
        if segment is None or len(segment.data) == 0:
            return True  # Overlap fully consumed
        
        # Insert in sorted order
        self._insert_sorted(segment)
        self._current_depth += len(segment.data)
        
        return True
    
    def _resolve_overlaps(self, new_seg: Segment) -> Optional[Segment]:
        """
        Resolve overlaps with existing segments based on policy.
        
        Returns modified segment or None if fully consumed.
        """
        if not self._segments:
            return new_seg
        
        modified_data = bytearray(new_seg.data)
        new_start = new_seg.seq
        new_end = new_seg.end_seq
        segments_to_remove = []
        
        for i, existing in enumerate(self._segments):
            # No overlap - segment is entirely before or after
            if new_end <= existing.seq or new_start >= existing.end_seq:
                continue
            
            self.stats["overlaps_resolved"] += 1
            
            # Calculate overlap region
            overlap_start = max(new_start, existing.seq)
            overlap_end = min(new_end, existing.end_seq)
            
            # Apply overlap policy
            if self.overlap_policy in (OverlapPolicy.BSD, OverlapPolicy.FIRST):
                # Favor existing (old) data - trim new segment
                if new_start < existing.seq:
                    # Keep portion before existing
                    keep_len = existing.seq - new_start
                    if new_end > existing.end_seq:
                        # New segment spans existing - keep both ends
                        after_start = existing.end_seq - new_start
                        modified_data = modified_data[:keep_len] + modified_data[after_start:]
                    else:
                        modified_data = modified_data[:keep_len]
                elif new_start >= existing.seq and new_end <= existing.end_seq:
                    # New segment entirely within existing - discard
                    return None
                else:
                    # New segment starts within, extends beyond
                    keep_start = existing.end_seq - new_start
                    modified_data = modified_data[keep_start:]
                    new_start = existing.end_seq
                    
            elif self.overlap_policy in (OverlapPolicy.LINUX, OverlapPolicy.LAST):
                # Favor new data - trim or split existing
                if existing.seq < new_start:
                    # Existing starts before - trim end
                    trim_at = new_start - existing.seq
                    self._segments[i] = Segment(
                        seq=existing.seq,
                        data=existing.data[:trim_at],
                        timestamp=existing.timestamp
                    )
                    self._current_depth -= len(existing.data) - trim_at
                    
                if existing.end_seq > new_end:
                    # Existing extends beyond - keep end portion
                    keep_start = new_end - existing.seq
                    after_seg = Segment(
                        seq=new_end,
                        data=existing.data[keep_start:],
                        timestamp=existing.timestamp
                    )
                    self._insert_sorted(after_seg)
                    
                if existing.seq >= new_start and existing.end_seq <= new_end:
                    # Existing entirely within new - mark for removal
                    segments_to_remove.append(i)
            
            elif self.overlap_policy == OverlapPolicy.WINDOWS:
                # Windows-specific: complex rules, simplified here
                # Generally favors old data but has edge cases
                if overlap_start == new_start:
                    # Overlap at start - favor old
                    trim = overlap_end - new_start
                    modified_data = modified_data[trim:]
                    new_start = overlap_end
        
        # Remove fully-overlapped segments (reverse order to maintain indices)
        for i in reversed(segments_to_remove):
            removed = self._segments.pop(i)
            self._current_depth -= len(removed.data)
        
        if len(modified_data) == 0:
            return None
        
        return Segment(seq=new_start, data=bytes(modified_data), timestamp=new_seg.timestamp)
    
    def _insert_sorted(self, segment: Segment) -> None:
        """Insert segment in sequence-number order."""
        # Find insertion point
        idx = bisect_left([s.seq for s in self._segments], segment.seq)
        self._segments.insert(idx, segment)
    
    def get_contiguous(self) -> Tuple[bytes, int]:
        """
        Get all contiguous in-order data available.
        
        Returns:
            Tuple of (data bytes, number of bytes delivered)
        """
        if not self._segments:
            return b"", 0
        
        result = bytearray()
        delivered = 0
        segments_to_remove = []
        
        for i, seg in enumerate(self._segments):
            # Gap - can't deliver more
            if seg.seq > self.next_seq:
                break
            
            # Segment starts at or before next_seq
            if seg.end_seq <= self.next_seq:
                # Already processed (retransmit) - remove
                segments_to_remove.append(i)
                continue
            
            # Extract new data portion
            if seg.seq < self.next_seq:
                # Partial overlap with already-delivered
                offset = self.next_seq - seg.seq
                new_data = seg.data[offset:]
            else:
                new_data = seg.data
            
            result.extend(new_data)
            self.next_seq = seg.end_seq
            delivered += len(new_data)
            segments_to_remove.append(i)
        
        # Remove delivered segments
        for i in reversed(segments_to_remove):
            removed = self._segments.pop(i)
            self._current_depth -= len(removed.data)
        
        if delivered:
            self.stats["segments_delivered"] += len(segments_to_remove)
            self.stats["bytes_delivered"] += delivered
        
        return bytes(result), delivered
    
    def get_gaps(self) -> List[Gap]:
        """
        Get list of gaps in the buffer.
        
        Returns gaps between next_seq and the end of buffered data.
        """
        gaps = []
        
        if not self._segments:
            return gaps
        
        current = self.next_seq
        
        for seg in self._segments:
            if seg.seq > current:
                gaps.append(Gap(start_seq=current, end_seq=seg.seq))
            if seg.end_seq > current:
                current = seg.end_seq
        
        if gaps:
            self.stats["gaps_detected"] = len(gaps)
        
        return gaps
    
    def has_gaps(self) -> bool:
        """Check if buffer has gaps."""
        if not self._segments:
            return False
        return self._segments[0].seq > self.next_seq
    
    def flush(self) -> bytes:
        """
        Force-flush all buffered data regardless of gaps.
        
        Used when stream is closing or on timeout.
        Returns all data in sequence order, with gaps filled with zeros.
        """
        if not self._segments:
            return b""
        
        result = bytearray()
        current = self.next_seq
        
        for seg in self._segments:
            if seg.seq > current:
                # Fill gap with zeros (or could skip)
                gap_size = seg.seq - current
                result.extend(b'\x00' * gap_size)
            
            # Handle overlap with already-added data
            if seg.seq < current:
                offset = current - seg.seq
                if offset < len(seg.data):
                    result.extend(seg.data[offset:])
            else:
                result.extend(seg.data)
            
            if seg.end_seq > current:
                current = seg.end_seq
        
        # Clear buffer
        delivered = self._current_depth
        self._segments.clear()
        self._current_depth = 0
        self.stats["bytes_delivered"] += delivered
        
        return bytes(result)
    
    @property
    def buffered_size(self) -> int:
        """Current bytes in buffer."""
        return self._current_depth
    
    @property
    def segment_count(self) -> int:
        """Current number of segments."""
        return len(self._segments)
    
    def clear(self) -> None:
        """Clear all buffered data."""
        self._segments.clear()
        self._current_depth = 0

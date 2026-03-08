"""
TCP Stream Reassembler (Suricata-Inspired)

Core reassembly engine that:
- Tracks TCP streams (1M+ concurrent)
- Reassembles out-of-order segments
- Handles retransmissions and overlaps
- Flushes data to Phase 3 callbacks
"""
import time
import threading
import logging
from dataclasses import dataclass, field
from typing import Dict, Optional, Callable, Any, Tuple
from collections import OrderedDict
import hashlib

from .config import StreamConfig, OverlapPolicy, get_default_config
from .stream import TCPStream, StreamState, Direction, SequenceTracker
from .buffer import SegmentBuffer
from .callbacks import (
    ReassembledStream, FlushReason, Phase3CallbackHandler,
    Phase3Callback, log_callback
)

logger = logging.getLogger(__name__)


@dataclass
class StreamEntry:
    """Entry in the stream table containing stream and its buffers."""
    stream: TCPStream
    client_buffer: SegmentBuffer  # Client to Server
    server_buffer: SegmentBuffer  # Server to Client
    chunk_counts: Dict[str, int] = field(default_factory=lambda: {"c2s": 0, "s2c": 0})


class TCPReassembler:
    """
    High-Performance TCP Stream Reassembler.
    
    Suricata-inspired design for enterprise deployments:
    - Sharded stream table for concurrent access
    - Memory-bounded operation
    - Configurable overlap policies
    - Automatic stream cleanup
    - Phase 3 callback integration
    
    Usage:
        reassembler = TCPReassembler(config=StreamConfig())
        reassembler.register_callback(my_phase3_handler)
        
        # In packet processing loop:
        reassembler.process_packet(parsed, payload, verdict)
    """
    
    NUM_SHARDS = 64  # Number of shards for concurrent access
    
    def __init__(
        self,
        config: Optional[StreamConfig] = None,
        phase3_callback: Optional[Phase3Callback] = None
    ):
        self.config = config or get_default_config()
        
        # Validate config
        if not self.config.validate():
            logger.warning("StreamConfig validation failed, using defaults")
            self.config = get_default_config()
        
        # Sharded stream tables (for reduced lock contention)
        self._shards: list[Dict[str, StreamEntry]] = [
            OrderedDict() for _ in range(self.NUM_SHARDS)
        ]
        self._shard_locks: list[threading.Lock] = [
            threading.Lock() for _ in range(self.NUM_SHARDS)
        ]
        
        # Global counters
        self._total_streams = 0
        self._total_lock = threading.Lock()
        
        # Memory tracking
        self._current_memory = 0
        self._memory_lock = threading.Lock()
        
        # Phase 3 callback handler
        self._callback_handler = Phase3CallbackHandler()
        if phase3_callback:
            self._callback_handler.register(phase3_callback)
        else:
            # Register default logging callback
            self._callback_handler.register(log_callback)
        
        # Statistics
        self.stats = {
            "packets_processed": 0,
            "streams_created": 0,
            "streams_closed": 0,
            "bytes_reassembled": 0,
            "data_chunks_sent": 0,
            "memory_evictions": 0,
            "timeout_evictions": 0
        }
        
        # Cleanup thread
        self._cleanup_running = False
        self._cleanup_thread: Optional[threading.Thread] = None
        
        logger.info(
            f"TCPReassembler initialized: "
            f"max_streams={self.config.max_streams}, "
            f"memcap={self.config.stream_memcap // (1024*1024)}MB, "
            f"policy={self.config.overlap_policy.value}"
        )
    
    def _get_shard_index(self, stream_id: str) -> int:
        """Get shard index for a stream ID using consistent hashing."""
        h = hashlib.md5(stream_id.encode(), usedforsecurity=False).digest()
        return int.from_bytes(h[:2], 'little') % self.NUM_SHARDS
    
    def _make_stream_id(
        self,
        src_ip: str, src_port: int,
        dst_ip: str, dst_port: int
    ) -> Tuple[str, str]:
        """
        Create canonical stream ID and reverse ID.
        
        Returns (forward_id, reverse_id)
        """
        forward = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        reverse = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
        return forward, reverse
    
    def register_callback(self, callback: Phase3Callback) -> None:
        """Register a Phase 3 callback function."""
        self._callback_handler.register(callback)
    
    def unregister_callback(self, callback: Phase3Callback) -> None:
        """Unregister a Phase 3 callback function."""
        self._callback_handler.unregister(callback)
    
    def process_packet(
        self,
        parsed: Any,  # ParsedPacket from packet_processor
        payload: bytes,
        dpi_verdict: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Process a TCP packet for stream reassembly.
        
        Args:
            parsed: Parsed packet with src_ip, dst_ip, src_port, dst_port,
                   syn, ack, fin, rst, seq_num, ack_num, window fields
            payload: TCP payload data
            dpi_verdict: DPI verdict dictionary (optional)
        
        This is the main entry point from the pipeline.
        """
        # Only handle TCP (protocol 6)
        if getattr(parsed, 'protocol', 0) != 6:
            return
        
        self.stats["packets_processed"] += 1
        
        # Extract packet info
        src_ip = parsed.src_ip
        dst_ip = parsed.dst_ip
        src_port = parsed.src_port or 0
        dst_port = parsed.dst_port or 0
        
        # Get TCP flags and sequence numbers
        syn = getattr(parsed, 'syn', False)
        ack = getattr(parsed, 'ack', False)
        fin = getattr(parsed, 'fin', False)
        rst = getattr(parsed, 'rst', False)
        seq_num = getattr(parsed, 'seq_num', 0)
        ack_num = getattr(parsed, 'ack_num', 0)
        window = getattr(parsed, 'window', 65535)
        
        # Create stream IDs
        forward_id, reverse_id = self._make_stream_id(
            src_ip, src_port, dst_ip, dst_port
        )
        
        # Find or create stream
        entry = self._get_or_create_stream(
            forward_id, reverse_id,
            src_ip, src_port, dst_ip, dst_port,
            syn, ack
        )
        
        if entry is None:
            return  # Stream limit reached
        
        stream = entry.stream
        
        # Determine direction
        direction = stream.get_direction(src_ip, src_port)
        
        # Update stream state
        new_state = stream.process_flags(syn, ack, fin, rst, direction)
        stream.update_state(new_state)
        stream.last_seen = time.time()
        
        # Store DPI verdict
        if dpi_verdict:
            stream.dpi_verdict = dpi_verdict
            if 'app_identified' in dpi_verdict:
                stream.app_protocol = dpi_verdict['app_identified']
        
        # Update sequence tracking and buffer data
        if direction == Direction.TO_SERVER:
            seq_tracker = stream.client_seq
            buffer = entry.client_buffer
        else:
            seq_tracker = stream.server_seq
            buffer = entry.server_buffer
        
        # Initialize ISN on first data
        if seq_tracker.isn == 0 and seq_num > 0:
            seq_tracker.isn = seq_num
            seq_tracker.next_seq = seq_num
            buffer.isn = seq_num
            buffer.next_seq = seq_num
        
        # Update sequence tracker
        payload_len = len(payload)
        seq_tracker.update(seq_num, payload_len, ack_num, window)
        
        # Buffer payload for reassembly
        if payload_len > 0:
            buffer.insert(seq_num, payload, time.time())
            
            # Check for contiguous data to flush
            contiguous_data, bytes_delivered = buffer.get_contiguous()
            
            if bytes_delivered >= self.config.min_flush_depth:
                self._flush_to_phase3(
                    entry, direction, contiguous_data,
                    FlushReason.DATA_READY
                )
        
        # Handle connection termination
        if rst and self.config.flush_on_rst:
            self._flush_stream(entry, FlushReason.RST_RECEIVED)
        elif fin and self.config.flush_on_fin:
            self._flush_stream(entry, FlushReason.FIN_RECEIVED)
        
        # Check if stream should be closed
        if stream.is_closed():
            self._close_stream(forward_id)
    
    def _get_or_create_stream(
        self,
        forward_id: str,
        reverse_id: str,
        src_ip: str, src_port: int,
        dst_ip: str, dst_port: int,
        syn: bool, ack: bool
    ) -> Optional[StreamEntry]:
        """
        Get existing stream or create new one.
        
        Handles both directions - a packet might match the reverse of an
        existing stream.
        """
        # Check forward direction
        shard_idx = self._get_shard_index(forward_id)
        
        with self._shard_locks[shard_idx]:
            if forward_id in self._shards[shard_idx]:
                entry = self._shards[shard_idx][forward_id]
                # Move to end (LRU)
                self._shards[shard_idx].move_to_end(forward_id)
                return entry
        
        # Check reverse direction
        reverse_shard_idx = self._get_shard_index(reverse_id)
        
        with self._shard_locks[reverse_shard_idx]:
            if reverse_id in self._shards[reverse_shard_idx]:
                entry = self._shards[reverse_shard_idx][reverse_id]
                self._shards[reverse_shard_idx].move_to_end(reverse_id)
                return entry
        
        # Create new stream (only on SYN or if midstream is enabled)
        if not syn and not self.config.midstream:
            return None
        
        # Check limits
        with self._total_lock:
            if self._total_streams >= self.config.max_streams:
                # Evict oldest stream
                self._evict_oldest()
                self.stats["memory_evictions"] += 1
            
            self._total_streams += 1
            self.stats["streams_created"] += 1
        
        # Create new stream and buffers
        stream = TCPStream(
            stream_id=forward_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port
        )
        
        client_buffer = SegmentBuffer(
            max_depth=self.config.reassembly_depth,
            overlap_policy=self.config.overlap_policy
        )
        
        server_buffer = SegmentBuffer(
            max_depth=self.config.reassembly_depth,
            overlap_policy=self.config.overlap_policy
        )
        
        entry = StreamEntry(
            stream=stream,
            client_buffer=client_buffer,
            server_buffer=server_buffer
        )
        
        # Insert into shard
        with self._shard_locks[shard_idx]:
            self._shards[shard_idx][forward_id] = entry
        
        logger.debug(f"New stream: {forward_id}")
        return entry
    
    def _flush_to_phase3(
        self,
        entry: StreamEntry,
        direction: Direction,
        data: bytes,
        reason: FlushReason
    ) -> None:
        """Send reassembled data chunk to Phase 3."""
        if not data:
            return
        
        stream = entry.stream
        dir_str = direction.value
        
        # Get and increment chunk count
        chunk_idx = entry.chunk_counts[dir_str]
        entry.chunk_counts[dir_str] += 1
        
        # Build output structure
        reassembled = ReassembledStream(
            stream_id=stream.stream_id,
            src_ip=stream.src_ip if direction == Direction.TO_SERVER else stream.dst_ip,
            dst_ip=stream.dst_ip if direction == Direction.TO_SERVER else stream.src_ip,
            src_port=stream.src_port if direction == Direction.TO_SERVER else stream.dst_port,
            dst_port=stream.dst_port if direction == Direction.TO_SERVER else stream.src_port,
            data=data,
            direction=dir_str,
            is_complete=stream.is_closed(),
            has_gaps=entry.client_buffer.has_gaps() or entry.server_buffer.has_gaps(),
            flush_reason=reason,
            chunk_index=chunk_idx,
            app_protocol=stream.app_protocol,
            dpi_verdict=stream.dpi_verdict,
            metadata=stream.metadata
        )
        
        # Send to callbacks
        self._callback_handler.send(reassembled)
        
        self.stats["bytes_reassembled"] += len(data)
        self.stats["data_chunks_sent"] += 1
    
    def _flush_stream(self, entry: StreamEntry, reason: FlushReason) -> None:
        """Force-flush all buffered data for a stream."""
        # Flush client buffer
        client_data = entry.client_buffer.flush()
        if client_data:
            self._flush_to_phase3(entry, Direction.TO_SERVER, client_data, reason)
        
        # Flush server buffer
        server_data = entry.server_buffer.flush()
        if server_data:
            self._flush_to_phase3(entry, Direction.TO_CLIENT, server_data, reason)
    
    def _close_stream(self, stream_id: str) -> None:
        """Remove a closed stream from tracking."""
        shard_idx = self._get_shard_index(stream_id)
        
        with self._shard_locks[shard_idx]:
            if stream_id in self._shards[shard_idx]:
                del self._shards[shard_idx][stream_id]
                
                with self._total_lock:
                    self._total_streams -= 1
                    self.stats["streams_closed"] += 1
    
    def _evict_oldest(self) -> None:
        """Evict oldest stream across all shards."""
        oldest_time = float('inf')
        oldest_id = None
        oldest_shard = None
        
        # Find oldest across all shards
        for i, shard in enumerate(self._shards):
            with self._shard_locks[i]:
                if shard:
                    # OrderedDict: first item is oldest
                    first_id = next(iter(shard))
                    entry = shard[first_id]
                    if entry.stream.last_seen < oldest_time:
                        oldest_time = entry.stream.last_seen
                        oldest_id = first_id
                        oldest_shard = i
        
        # Remove oldest
        if oldest_id and oldest_shard is not None:
            with self._shard_locks[oldest_shard]:
                if oldest_id in self._shards[oldest_shard]:
                    entry = self._shards[oldest_shard].pop(oldest_id)
                    # Flush any remaining data
                    self._flush_stream(entry, FlushReason.MEMORY_PRESSURE)
                    logger.debug(f"Evicted stream: {oldest_id}")
    
    def start_cleanup_thread(self) -> None:
        """Start background thread for cleaning up expired streams."""
        if self._cleanup_running:
            return
        
        self._cleanup_running = True
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True,
            name="tcp-reassembler-cleanup"
        )
        self._cleanup_thread.start()
        logger.info("Cleanup thread started")
    
    def stop_cleanup_thread(self) -> None:
        """Stop the cleanup thread."""
        self._cleanup_running = False
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=5.0)
            self._cleanup_thread = None
    
    def _cleanup_loop(self) -> None:
        """Background loop for stream cleanup."""
        while self._cleanup_running:
            try:
                self._cleanup_expired()
                time.sleep(30)  # Run every 30 seconds
            except Exception as e:
                logger.error(f"Cleanup error: {e}")
    
    def _cleanup_expired(self) -> None:
        """Remove expired streams based on timeouts."""
        now = time.time()
        expired_count = 0
        
        for i, shard in enumerate(self._shards):
            to_remove = []
            
            with self._shard_locks[i]:
                for stream_id, entry in shard.items():
                    stream = entry.stream
                    
                    # Determine timeout based on state
                    if stream.is_established():
                        timeout = self.config.stream_established_timeout
                    elif stream.is_closed():
                        timeout = self.config.stream_closed_timeout
                    else:
                        timeout = self.config.stream_timeout
                    
                    if now - stream.last_seen > timeout:
                        to_remove.append(stream_id)
                
                # Remove expired
                for stream_id in to_remove:
                    entry = shard.pop(stream_id)
                    self._flush_stream(entry, FlushReason.TIMEOUT)
                    expired_count += 1
        
        if expired_count:
            with self._total_lock:
                self._total_streams -= expired_count
                self.stats["timeout_evictions"] += expired_count
            logger.debug(f"Cleaned up {expired_count} expired streams")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get reassembler statistics."""
        callback_stats = self._callback_handler.get_stats()
        
        return {
            **self.stats,
            "active_streams": self._total_streams,
            "phase3_streams_sent": callback_stats["streams_sent"],
            "phase3_bytes_sent": callback_stats["bytes_sent"],
            "phase3_errors": callback_stats["callback_errors"]
        }
    
    def get_stream(self, stream_id: str) -> Optional[TCPStream]:
        """Get stream by ID (for debugging/inspection)."""
        shard_idx = self._get_shard_index(stream_id)
        
        with self._shard_locks[shard_idx]:
            if stream_id in self._shards[shard_idx]:
                return self._shards[shard_idx][stream_id].stream
        
        return None
        
    

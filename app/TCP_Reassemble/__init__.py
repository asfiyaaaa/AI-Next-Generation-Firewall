"""
TCP Stream Reassembly Module (Suricata-Inspired)

High-performance TCP stream reassembly for NGFW pipeline.
Designed for 1M+ concurrent connections with enterprise-grade features.

Features:
- Out-of-order segment handling
- Retransmission deduplication
- Configurable overlap resolution (BSD/Linux/Windows policies)
- Memory-bounded operation
- Automatic stream timeout and cleanup
- Phase 3 callback integration

Usage:
    from app.TCP_Reassemble import TCPReassembler, StreamConfig, ReassembledStream
    
    # Create reassembler with default config
    reassembler = TCPReassembler()
    
    # Register Phase 3 callback
    reassembler.register_callback(my_phase3_handler)
    
    # Process packets (called from pipeline)
    reassembler.process_packet(parsed, payload, dpi_verdict)
"""

# Configuration
from .config import (
    StreamConfig,
    OverlapPolicy,
    StreamPolicy,
    get_default_config,
    get_low_memory_config,
    get_high_security_config
)

# Stream state machine
from .stream import (
    TCPStream,
    StreamState,
    Direction,
    SequenceTracker,
    EvasionFlag
)

# Segment buffer
from .buffer import (
    SegmentBuffer,
    Segment,
    Gap
)

# Phase 3 callbacks
from .callbacks import (
    ReassembledStream,
    FlushReason,
    Phase3Callback,
    Phase3CallbackHandler,
    Phase3Integration,
    log_callback,
    null_callback
)

# Main reassembler
from .reassembler import (
    TCPReassembler,
    StreamEntry
)

__all__ = [
    # Config
    'StreamConfig',
    'OverlapPolicy', 
    'StreamPolicy',
    'get_default_config',
    'get_low_memory_config',
    'get_high_security_config',
    
    # Stream
    'TCPStream',
    'StreamState',
    'Direction',
    'SequenceTracker',
    'EvasionFlag',
    
    # Buffer
    'SegmentBuffer',
    'Segment',
    'Gap',
    
    # Callbacks
    'ReassembledStream',
    'FlushReason',
    'Phase3Callback',
    'Phase3CallbackHandler',
    'Phase3Integration',
    'log_callback',
    'null_callback',
    
    # Reassembler
    'TCPReassembler',
    'StreamEntry',
]

__version__ = '1.0.0'

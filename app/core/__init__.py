"""
Phase1 Package - Windows Only (WinDivert)

6 Core Feature Modules:
1. capture       - Packet capture, parsing, processing (WinDivert)
2. inspection    - Stateful packet inspection, attack detection
3. connection    - Connection tracking table (2M+ connections)
4. nat           - NAT engine, table, port pool
5. rules         - Rule engine, models, parser
6. datastructures - Flow cache, IP sets
"""

# =============================================================================
# 1. CAPTURE (Packet Capture Engine)
# =============================================================================
from .capture import (
    CaptureAction, CaptureStats,
    WinDivertCapture, MockWinDivertCapture,
    PacketCapture, MockPacketCapture, CAPTURE_BACKEND
)

from .packet_processor import (
    ParsedPacket, PacketParser, PacketProcessor
)

# =============================================================================
# 2. INSPECTION (Stateful Packet Inspection)
# =============================================================================
from .inspection import (
    AttackDetector, AttackStats, InspectionResult, SPIEngine,
    record_syn, record_ack, record_half_open, clear_half_open, analyze_packet
)

# =============================================================================
# 3. CONNECTION (Connection Tracking)
# =============================================================================
from .connection import (
    ConnectionTable, Connection, ConnectionState, ConnectionShard
)

# =============================================================================
# 4. NAT (Network Address Translation)
# =============================================================================
from .nat import (
    NATEngine, NATRule, NATType,
    NATTable, NATMapping,
    PortPool, PortAllocation
)

# =============================================================================
# 5. RULES (Rule Engine)
# =============================================================================
from .rules import (
    RuleEngine, PacketInfo, RuleMatch,
    FirewallRule, Action, Protocol, Direction, PortRange,
    ConnectionStateMatch, TimeRange, DefaultRules,
    RuleParser, RuleParseError, create_sample_config
)

# =============================================================================
# 6. DATASTRUCTURES (High-Performance Data Structures)
# =============================================================================
from .datastructures import (
    FlowCache, BidirectionalFlowCache, CachedAction, CacheEntry,
    IPSet, CIDRTree, IPRange, WellKnownIPSets
)


__all__ = [
    # Capture
    'CaptureAction', 'CaptureStats', 'ParsedPacket', 'PacketParser',
    'WinDivertCapture', 'MockWinDivertCapture', 'PacketProcessor',
    'PacketCapture', 'MockPacketCapture', 'CAPTURE_BACKEND',
    
    # Inspection
    'AttackDetector', 'AttackStats', 'InspectionResult', 'SPIEngine',
    'record_syn', 'record_ack', 'record_half_open', 'clear_half_open', 'analyze_packet',
    
    # Connection
    'ConnectionTable', 'Connection', 'ConnectionState', 'ConnectionShard',
    
    # NAT
    'NATEngine', 'NATRule', 'NATType',
    'NATTable', 'NATMapping',
    'PortPool', 'PortAllocation',
    
    # Rules
    'RuleEngine', 'PacketInfo', 'RuleMatch',
    'FirewallRule', 'Action', 'Protocol', 'Direction', 'PortRange',
    'ConnectionStateMatch', 'TimeRange', 'DefaultRules',
    'RuleParser', 'RuleParseError', 'create_sample_config',
    
    # Data structures
    'FlowCache', 'BidirectionalFlowCache', 'CachedAction', 'CacheEntry',
    'IPSet', 'CIDRTree', 'IPRange', 'WellKnownIPSets',
]

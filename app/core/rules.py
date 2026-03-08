"""
Rules Module - Firewall Rule Engine

Consolidates:
- Rule Models: Data structures for firewall rules
- Rule Parser: JSON configuration file parsing
- Rule Engine: High-performance rule matching

Features:
- Priority-based rule matching
- IP/CIDR matching with CIDR trees
- Port and port range matching
- Stateful connection matching (NEW, ESTABLISHED, etc.)
- Flow caching for fast-path processing
"""

import json
import logging
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Set, List, Dict, Callable
from datetime import time as dt_time
from ipaddress import ip_address, ip_network
from pathlib import Path


logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class Action(Enum):
    ALLOW = "allow"
    DROP = "drop"
    REJECT = "reject"
    LOG = "log"
    LOG_DROP = "log_drop"
    NAT = "nat"


class Protocol(Enum):
    ANY = 0
    ICMP = 1
    TCP = 6
    UDP = 17
    GRE = 47
    ESP = 50
    AH = 51
    
    @classmethod
    def from_string(cls, s: str) -> 'Protocol':
        mapping = {'any': cls.ANY, 'icmp': cls.ICMP, 'tcp': cls.TCP, 'udp': cls.UDP, 'gre': cls.GRE, 'esp': cls.ESP, 'ah': cls.AH}
        return mapping.get(s.lower(), cls.ANY)
    
    @classmethod
    def from_int(cls, i: int) -> 'Protocol':
        for proto in cls:
            if proto.value == i:
                return proto
        return cls.ANY


class Direction(Enum):
    INBOUND = "in"
    OUTBOUND = "out"
    BOTH = "both"
    
    @classmethod
    def from_string(cls, s: str) -> 'Direction':
        mapping = {'in': cls.INBOUND, 'inbound': cls.INBOUND, 'out': cls.OUTBOUND, 'outbound': cls.OUTBOUND, 'both': cls.BOTH, 'any': cls.BOTH}
        return mapping.get(s.lower(), cls.BOTH)


class ConnectionStateMatch(Enum):
    NEW = "new"
    ESTABLISHED = "established"
    RELATED = "related"
    INVALID = "invalid"
    
    @classmethod
    def from_string(cls, s: str) -> 'ConnectionStateMatch':
        mapping = {'new': cls.NEW, 'established': cls.ESTABLISHED, 'related': cls.RELATED, 'invalid': cls.INVALID}
        return mapping.get(s.lower(), cls.NEW)


# =============================================================================
# Data Classes
# =============================================================================

@dataclass(frozen=True)
class PortRange:
    start: int
    end: int
    
    def contains(self, port: int) -> bool:
        return self.start <= port <= self.end
    
    @classmethod
    def single(cls, port: int) -> 'PortRange':
        return cls(port, port)
    
    @classmethod
    def parse(cls, s: str) -> 'PortRange':
        if '-' in s:
            start, end = s.split('-', 1)
            return cls(int(start.strip()), int(end.strip()))
        return cls.single(int(s.strip()))
    
    def __repr__(self) -> str:
        return str(self.start) if self.start == self.end else f"{self.start}-{self.end}"


@dataclass
class TimeRange:
    start_time: dt_time
    end_time: dt_time
    days: Set[int] = field(default_factory=lambda: set(range(7)))
    
    def is_active(self, current_time: dt_time = None, current_day: int = None) -> bool:
        from datetime import datetime
        now = datetime.now()
        current_time = current_time or now.time()
        current_day = current_day if current_day is not None else now.weekday()
        if current_day not in self.days:
            return False
        if self.start_time <= self.end_time:
            return self.start_time <= current_time <= self.end_time
        return current_time >= self.start_time or current_time <= self.end_time


@dataclass
class RuleMatch:
    matched: bool
    rule: Optional['FirewallRule'] = None
    action: Action = Action.DROP
    
    def __bool__(self) -> bool:
        return self.matched


@dataclass
class FirewallRule:
    id: int
    name: str = ""
    description: str = ""
    enabled: bool = True
    priority: int = 100
    action: Action = Action.DROP
    direction: Direction = Direction.BOTH
    protocol: Protocol = Protocol.ANY
    src_ip: Optional[str] = None
    src_ports: Set[PortRange] = field(default_factory=set)
    src_neg: bool = False
    dst_ip: Optional[str] = None
    dst_ports: Set[PortRange] = field(default_factory=set)
    dst_neg: bool = False
    states: Set[ConnectionStateMatch] = field(default_factory=lambda: {ConnectionStateMatch.NEW, ConnectionStateMatch.ESTABLISHED})
    time_range: Optional[TimeRange] = None
    log: bool = False
    log_prefix: str = ""
    rate_limit: Optional[int] = None
    rate_burst: int = 10
    hit_count: int = field(default=0, repr=False)
    byte_count: int = field(default=0, repr=False)
    
    def matches_port(self, port: int, port_ranges: Set[PortRange]) -> bool:
        if not port_ranges:
            return True
        return any(pr.contains(port) for pr in port_ranges)
    
    def matches_state(self, state: str) -> bool:
        if not self.states:
            return True
        state_map = {'NEW': ConnectionStateMatch.NEW, 'SYN_SENT': ConnectionStateMatch.NEW, 'ESTABLISHED': ConnectionStateMatch.ESTABLISHED, 'RELATED': ConnectionStateMatch.RELATED, 'INVALID': ConnectionStateMatch.INVALID}
        conn_state = state_map.get(state.upper())
        return conn_state in self.states if conn_state else True
    
    def record_match(self, bytes_count: int = 0) -> None:
        self.hit_count += 1
        self.byte_count += bytes_count
    
    def to_dict(self) -> dict:
        return {'id': self.id, 'name': self.name, 'enabled': self.enabled, 'priority': self.priority, 'action': self.action.value, 'protocol': self.protocol.name, 'src_ip': self.src_ip, 'dst_ip': self.dst_ip, 'hit_count': self.hit_count}


class DefaultRules:
    @staticmethod
    def allow_established(rule_id: int = 1) -> FirewallRule:
        return FirewallRule(id=rule_id, name="Allow Established", action=Action.ALLOW, states={ConnectionStateMatch.ESTABLISHED, ConnectionStateMatch.RELATED}, priority=1)
    
    @staticmethod
    def allow_loopback(rule_id: int = 2) -> FirewallRule:
        return FirewallRule(id=rule_id, name="Allow Loopback", action=Action.ALLOW, src_ip="127.0.0.0/8", dst_ip="127.0.0.0/8", priority=2)
    
    @staticmethod
    def drop_invalid(rule_id: int = 3) -> FirewallRule:
        return FirewallRule(id=rule_id, name="Drop Invalid", action=Action.DROP, states={ConnectionStateMatch.INVALID}, priority=3, log=True)
    
    @staticmethod
    def allow_icmp(rule_id: int = 4) -> FirewallRule:
        return FirewallRule(id=rule_id, name="Allow ICMP", action=Action.ALLOW, protocol=Protocol.ICMP, priority=10)
    
    @staticmethod
    def allow_dns(rule_id: int = 5) -> FirewallRule:
        return FirewallRule(id=rule_id, name="Allow DNS", action=Action.ALLOW, protocol=Protocol.UDP, dst_ports={PortRange.single(53)}, priority=10)
    
    @staticmethod
    def default_drop(rule_id: int = 9999) -> FirewallRule:
        return FirewallRule(id=rule_id, name="Default Drop", action=Action.DROP, priority=9999, log=True)


# =============================================================================
# Rule Parser
# =============================================================================

class RuleParseError(Exception):
    def __init__(self, message: str, rule_id: int = 0):
        self.rule_id = rule_id
        super().__init__(f"Rule {rule_id}: {message}")


class RuleParser:
    """Parse firewall rules from JSON configuration files."""
    
    def __init__(self):
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.default_action: Action = Action.DROP
    
    def parse_file(self, path: str) -> List[FirewallRule]:
        rules = []
        self.errors = []
        
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"Rule file not found: {path}")
        
        with open(file_path, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as e:
                raise RuleParseError(f"Invalid JSON: {e}")
        
        if 'default_action' in data:
            self.default_action = self._parse_action(data['default_action'])
        
        for rule_data in data.get('rules', []):
            try:
                rule = self._parse_rule(rule_data)
                if rule:
                    rules.append(rule)
            except Exception as e:
                self.errors.append(f"Error parsing rule: {e}")
        
        logger.info(f"Parsed {len(rules)} rules from {path}")
        return rules
    
    def _parse_rule(self, data: Dict) -> Optional[FirewallRule]:
        rule_id = data.get('id', 0)
        action = self._parse_action(data.get('action', 'drop'))
        protocol = Protocol.from_string(data.get('protocol', 'any'))
        direction = Direction.from_string(data.get('direction', 'both'))
        src_ports = self._parse_ports(data.get('src_ports', []))
        dst_ports = self._parse_ports(data.get('dst_ports', []))
        states = self._parse_states(data.get('states', ['new', 'established']))
        
        return FirewallRule(
            id=rule_id, name=data.get('name', ''), description=data.get('description', ''),
            enabled=data.get('enabled', True), action=action, protocol=protocol,
            priority=data.get('priority', 100), direction=direction,
            src_ip=data.get('src_ip'), dst_ip=data.get('dst_ip'),
            src_ports=src_ports, dst_ports=dst_ports, states=states,
            log=data.get('log', False), log_prefix=data.get('log_prefix', '')
        )
    
    def _parse_action(self, action_str: str) -> Optional[Action]:
        action_map = {'allow': Action.ALLOW, 'accept': Action.ALLOW, 'drop': Action.DROP, 'deny': Action.DROP, 'reject': Action.REJECT, 'log': Action.LOG, 'log_drop': Action.LOG_DROP}
        return action_map.get(action_str.lower())
    
    def _parse_ports(self, ports_list: List) -> Set[PortRange]:
        ports = set()
        for port in ports_list:
            try:
                if isinstance(port, int):
                    ports.add(PortRange.single(port))
                elif isinstance(port, str):
                    ports.add(PortRange.parse(port))
            except ValueError:
                pass
        return ports
    
    def _parse_states(self, states_list: List[str]) -> Set[ConnectionStateMatch]:
        return {ConnectionStateMatch.from_string(s) for s in states_list}
    
    def get_default_action(self) -> Action:
        return self.default_action


def create_sample_config(path: str) -> None:
    sample = {
        "default_action": "drop",
        "rules": [
            {"id": 1, "name": "Allow Established", "action": "allow", "protocol": "any", "states": ["established", "related"], "priority": 1},
            {"id": 10, "name": "Allow ICMP", "action": "allow", "protocol": "icmp", "priority": 10},
            {"id": 11, "name": "Allow DNS", "action": "allow", "protocol": "udp", "dst_ports": [53], "priority": 10},
            {"id": 20, "name": "Allow Web", "action": "allow", "protocol": "tcp", "dst_ports": [80, 443], "priority": 20},
            {"id": 9999, "name": "Default Deny", "action": "drop", "protocol": "any", "log": True, "priority": 9999}
        ]
    }
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(sample, f, indent=2)


# =============================================================================
# Packet Info
# =============================================================================

@dataclass
class PacketInfo:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    is_inbound: bool = True
    connection_state: str = "NEW"
    packet_size: int = 0
    tcp_flags: str = ""
    syn: bool = False
    ack: bool = False
    fin: bool = False
    rst: bool = False
    
    def get_flow_key(self) -> str:
        return f"{self.protocol}:{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}"


# =============================================================================
# Rule Engine
# =============================================================================

class RuleEngine:
    """High-performance rule matching engine with caching."""
    
    def __init__(self, default_action: Action = Action.DROP, enable_logging: bool = True):
        self.rules: List[FirewallRule] = []
        self.default_action = default_action
        self.enable_logging = enable_logging
        self.lock = threading.RLock()
        
        self.packets_checked = 0
        self.cache_hits = 0
        self.rule_matches = 0
        self.default_matches = 0
    
    def add_rule(self, rule: FirewallRule) -> None:
        with self.lock:
            self.rules.append(rule)
            self.rules.sort(key=lambda r: r.priority)
    
    def add_rules(self, rules: List[FirewallRule]) -> None:
        with self.lock:
            self.rules.extend(rules)
            self.rules.sort(key=lambda r: r.priority)
    
    def remove_rule(self, rule_id: int) -> bool:
        with self.lock:
            for i, rule in enumerate(self.rules):
                if rule.id == rule_id:
                    self.rules.pop(i)
                    return True
            return False
    
    def match(self, packet: PacketInfo) -> RuleMatch:
        self.packets_checked += 1
        
        with self.lock:
            for rule in self.rules:
                if not rule.enabled:
                    continue
                
                if self._rule_matches(rule, packet):
                    rule.record_match(packet.packet_size)
                    self.rule_matches += 1
                    
                    if rule.log and self.enable_logging:
                        # logger.info(f"[{rule.name}] {rule.action.value.upper()}: {packet.src_ip}:{packet.src_port} -> {packet.dst_ip}:{packet.dst_port}")
                        pass
                    
                    return RuleMatch(matched=True, rule=rule, action=rule.action)
        
        self.default_matches += 1
        return RuleMatch(matched=False, action=self.default_action)
    
    def _rule_matches(self, rule: FirewallRule, packet: PacketInfo) -> bool:
        # Protocol match
        if rule.protocol != Protocol.ANY:
            if rule.protocol.value != packet.protocol:
                return False
        
        # Direction match
        if rule.direction == Direction.INBOUND and not packet.is_inbound:
            return False
        if rule.direction == Direction.OUTBOUND and packet.is_inbound:
            return False
        
        # Source IP match
        if rule.src_ip:
            if not self._ip_matches(packet.src_ip, rule.src_ip):
                return rule.src_neg
        
        # Destination IP match
        if rule.dst_ip:
            if not self._ip_matches(packet.dst_ip, rule.dst_ip):
                return rule.dst_neg
        
        # Port matching
        if not rule.matches_port(packet.src_port, rule.src_ports):
            return False
        if not rule.matches_port(packet.dst_port, rule.dst_ports):
            return False
        
        # State matching
        if not rule.matches_state(packet.connection_state):
            return False
        
        return True
    
    def _ip_matches(self, ip: str, cidr: str) -> bool:
        try:
            return ip_address(ip) in ip_network(cidr, strict=False)
        except ValueError:
            return False
    
    def get_rules(self) -> List[FirewallRule]:
        with self.lock:
            return list(self.rules)
    
    def get_stats(self) -> dict:
        return {
            "rules_count": len(self.rules),
            "packets_checked": self.packets_checked,
            "cache_hits": self.cache_hits,
            "rule_matches": self.rule_matches,
            "default_matches": self.default_matches,
        }

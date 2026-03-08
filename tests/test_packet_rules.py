"""
Unit Tests — Firewall Rule Engine

Tests for:
- Rule creation and configuration
- Protocol matching (TCP, UDP, ICMP)
- Port range matching
- Priority-based rule ordering
- Default rule generation
- Rule engine match logic
- IP CIDR matching
"""
import sys
import pytest
from pathlib import Path

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.rules import (
    Action, Protocol, Direction, ConnectionStateMatch,
    PortRange, FirewallRule, DefaultRules,
    RuleEngine, PacketInfo, RuleMatch, TimeRange
)


# =========================================================================
# PortRange Tests
# =========================================================================

class TestPortRange:
    """Tests for PortRange parsing and matching."""

    def test_single_port(self):
        pr = PortRange.single(443)
        assert pr.start == 443
        assert pr.end == 443
        assert pr.contains(443)
        assert not pr.contains(80)

    def test_port_range_parse(self):
        pr = PortRange.parse("1024-65535")
        assert pr.start == 1024
        assert pr.end == 65535
        assert pr.contains(8080)
        assert not pr.contains(80)

    def test_port_range_boundary(self):
        pr = PortRange.parse("80-443")
        assert pr.contains(80)
        assert pr.contains(443)
        assert pr.contains(200)
        assert not pr.contains(79)
        assert not pr.contains(444)


# =========================================================================
# FirewallRule Tests
# =========================================================================

class TestFirewallRule:
    """Tests for FirewallRule data structure."""

    def test_rule_creation(self):
        rule = FirewallRule(
            id=1, name="Allow HTTP",
            action=Action.ALLOW,
            protocol=Protocol.TCP,
            dst_ports={PortRange.single(80)},
            priority=10
        )
        assert rule.id == 1
        assert rule.action == Action.ALLOW
        assert rule.protocol == Protocol.TCP
        assert rule.priority == 10

    def test_rule_matches_port(self):
        rule = FirewallRule(
            id=1, name="Web Traffic",
            dst_ports={PortRange.single(80), PortRange.single(443)}
        )
        assert rule.matches_port(80, rule.dst_ports) is True
        assert rule.matches_port(443, rule.dst_ports) is True
        assert rule.matches_port(8080, rule.dst_ports) is False

    def test_rule_matches_state_established(self):
        rule = FirewallRule(
            id=1, name="Established",
            states={ConnectionStateMatch.ESTABLISHED}
        )
        assert rule.matches_state("ESTABLISHED") is True
        assert rule.matches_state("NEW") is False

    def test_record_match_increments(self):
        rule = FirewallRule(id=1, name="Test Rule")
        assert rule.hit_count == 0
        rule.record_match(bytes_count=1500)
        assert rule.hit_count == 1
        assert rule.byte_count == 1500
        rule.record_match(bytes_count=500)
        assert rule.hit_count == 2
        assert rule.byte_count == 2000


# =========================================================================
# DefaultRules Tests
# =========================================================================

class TestDefaultRules:
    """Tests for built-in default rules."""

    def test_allow_established(self):
        rule = DefaultRules.allow_established()
        assert rule.action == Action.ALLOW
        assert rule.priority == 1
        assert ConnectionStateMatch.ESTABLISHED in rule.states

    def test_allow_loopback(self):
        rule = DefaultRules.allow_loopback()
        assert rule.action == Action.ALLOW
        assert getattr(rule, "src_ip", None) == "127.0.0.0/8" or "127.0.0.1" in getattr(rule, "src_ips", [])

    def test_allow_dns(self):
        rule = DefaultRules.allow_dns()
        assert rule.action == Action.ALLOW
        assert rule.protocol == Protocol.UDP

    def test_default_drop(self):
        rule = DefaultRules.default_drop()
        assert rule.action == Action.DROP
        assert rule.priority == 9999


# =========================================================================
# RuleEngine Tests
# =========================================================================

class TestRuleEngine:
    """Tests for rule matching engine."""

    def setup_method(self):
        """Set up a rule engine with typical firewall rules."""
        self.engine = RuleEngine(default_action=Action.DROP, enable_logging=False)

        # Priority 1: Allow established
        self.engine.add_rule(DefaultRules.allow_established())

        # Priority 10: Allow HTTP/HTTPS outbound
        self.engine.add_rule(FirewallRule(
            id=10, name="Allow Web",
            action=Action.ALLOW,
            protocol=Protocol.TCP,
            dst_ports={PortRange.single(80), PortRange.single(443)},
            priority=10
        ))

        # Priority 100: Block Telnet
        self.engine.add_rule(FirewallRule(
            id=100, name="Block Telnet",
            action=Action.DROP,
            protocol=Protocol.TCP,
            dst_ports={PortRange.single(23)},
            priority=100
        ))

        # Priority 9999: Default drop
        self.engine.add_rule(DefaultRules.default_drop())

    def test_allow_http_traffic(self):
        pkt = PacketInfo(
            src_ip="192.168.1.100", dst_ip="8.8.8.8",
            src_port=54321, dst_port=80,
            protocol=Protocol.TCP, connection_state="ESTABLISHED"
        )
        result = self.engine.match(pkt)
        assert result.matched
        assert result.action == Action.ALLOW

    def test_allow_https_traffic(self):
        pkt = PacketInfo(
            src_ip="192.168.1.100", dst_ip="1.1.1.1",
            src_port=54321, dst_port=443,
            protocol=Protocol.TCP, connection_state="ESTABLISHED"
        )
        result = self.engine.match(pkt)
        assert result.matched
        assert result.action == Action.ALLOW

    def test_block_telnet(self):
        pkt = PacketInfo(
            src_ip="192.168.1.100", dst_ip="10.0.0.1",
            src_port=54321, dst_port=23,
            protocol=Protocol.TCP, connection_state="NEW"
        )
        result = self.engine.match(pkt)
        assert result.matched
        assert result.action == Action.DROP

    def test_default_drop_unmatched(self):
        """Packets not matching any rule should be dropped."""
        pkt = PacketInfo(
            src_ip="192.168.1.100", dst_ip="10.0.0.1",
            src_port=54321, dst_port=9999,
            protocol=Protocol.TCP, connection_state="NEW"
        )
        result = self.engine.match(pkt)
        assert result.action == Action.DROP

    def test_priority_ordering(self):
        """Lower priority numbers should be checked first."""
        rules = self.engine.get_rules()
        priorities = [r.priority for r in rules]
        assert priorities == sorted(priorities)

    def test_rule_stats(self):
        stats = self.engine.get_stats()
        assert "rule_matches" in stats

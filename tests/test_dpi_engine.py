"""
Unit Tests — DPI Engine & Verdict Aggregation

Tests for:
- InspectionContext creation
- DPI verdict logic (ALLOW/BLOCK decisions)
- Stage result processing
- Risk score calculation
- Threat detection scenarios
"""
import sys
import pytest
from pathlib import Path

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.dpi.constants import Decision, Severity, ContentType, DPIStage
from app.dpi.context import (
    InspectionContext, ConnectionMetadata, TLSMetadata,
    ApplicationResult, SignatureResult, SignatureMatch,
    IPSResult, TLSInspectionResult, AnomalyResult, ThreatIntelResult
)
from app.dpi.verdict import DPIVerdict, aggregate_verdict


# =========================================================================
# InspectionContext Tests
# =========================================================================

class TestInspectionContext:
    """Tests for the DPI inspection context data structure."""

    def _make_context(self, payload: bytes = b"GET / HTTP/1.1\r\n") -> InspectionContext:
        return InspectionContext(
            raw_payload=payload,
            content_type_hint=ContentType.TEXT,
            metadata=ConnectionMetadata(
                src_ip="192.168.1.100",
                dst_ip="93.184.216.34",
                src_port=54321,
                dst_port=80,
                protocol="TCP"
            )
        )

    def test_context_creation(self):
        ctx = self._make_context()
        assert ctx.metadata.src_ip == "192.168.1.100"
        assert ctx.metadata.dst_port == 80
        assert ctx.content_type_hint == ContentType.TEXT

    def test_initial_results_are_clean(self):
        ctx = self._make_context()
        assert ctx.app_result.application == "Unknown"
        assert ctx.ips_result.triggered is False
        assert ctx.signature_result.has_matches is False
        assert ctx.threat_intel_result.hit is False

    def test_mark_stage_complete(self):
        ctx = self._make_context()
        ctx.mark_stage_complete("normalization")
        ctx.mark_stage_complete("application_id")
        assert "normalization" in ctx.stages_completed
        assert "application_id" in ctx.stages_completed
        assert len(ctx.stages_completed) == 2

    def test_no_duplicate_stages(self):
        ctx = self._make_context()
        ctx.mark_stage_complete("normalization")
        ctx.mark_stage_complete("normalization")
        assert ctx.stages_completed.count("normalization") == 1

    def test_add_error(self):
        ctx = self._make_context()
        ctx.add_error("Stage timeout exceeded")
        assert len(ctx.errors) == 1
        assert "timeout" in ctx.errors[0].lower()

    def test_get_inspection_text_from_payload(self):
        ctx = self._make_context(b"GET /index.html HTTP/1.1\r\n")
        text = ctx.get_inspection_text()
        assert "GET /index.html" in text


# =========================================================================
# DPIVerdict Tests
# =========================================================================

class TestDPIVerdict:
    """Tests for DPI verdict structure."""

    def test_verdict_to_dict(self):
        verdict = DPIVerdict(
            decision=Decision.ALLOW,
            reason="No threats detected",
            confidence=0.95,
            risk_score=0.05
        )
        d = verdict.to_dict()
        assert d["decision"] == "ALLOW"
        assert d["reason"] == "No threats detected"
        assert d["confidence"] == 0.95

    def test_block_verdict(self):
        verdict = DPIVerdict(
            decision=Decision.BLOCK,
            reason="SQL Injection detected",
            confidence=0.99,
            features_triggered=["ips"],
            risk_score=0.95
        )
        assert verdict.decision == Decision.BLOCK
        assert "ips" in verdict.features_triggered


# =========================================================================
# Verdict Aggregation Tests
# =========================================================================

class TestVerdictAggregation:
    """Tests for the aggregate_verdict function — core detection logic."""

    def _make_clean_context(self) -> InspectionContext:
        return InspectionContext(
            raw_payload=b"GET / HTTP/1.1\r\n",
            content_type_hint=ContentType.TEXT,
            metadata=ConnectionMetadata(
                src_ip="192.168.1.100", dst_ip="93.184.216.34",
                src_port=54321, dst_port=80, protocol="TCP"
            )
        )

    def test_clean_traffic_is_allowed(self):
        """Normal traffic with no threats should be ALLOWED."""
        ctx = self._make_clean_context()
        verdict = aggregate_verdict(ctx)
        assert verdict.decision == Decision.ALLOW
        assert verdict.risk_score < 0.5

    def test_ips_trigger_blocks_traffic(self):
        """IPS detection should immediately block traffic."""
        ctx = self._make_clean_context()
        ctx.ips_result = IPSResult(
            triggered=True,
            attack_type="SQL Injection",
            severity=Severity.CRITICAL,
            confidence=0.98
        )
        verdict = aggregate_verdict(ctx)
        assert verdict.decision == Decision.BLOCK
        assert "ips" in verdict.features_triggered
        assert verdict.risk_score >= 0.8

    def test_malicious_tls_fingerprint_blocks(self):
        """Known malware TLS fingerprint should block."""
        ctx = self._make_clean_context()
        ctx.tls_result = TLSInspectionResult(
            suspicious_fingerprint=True,
            risk_score=0.95
        )
        verdict = aggregate_verdict(ctx)
        assert verdict.decision == Decision.BLOCK
        assert "tls_inspection" in verdict.features_triggered

    def test_signature_match_blocks(self):
        """Signature match should trigger blocking."""
        ctx = self._make_clean_context()
        ctx.signature_result = SignatureResult(
            matches=[SignatureMatch(id=1, name="Trojan.Gen", offset=0, severity=Severity.HIGH)],
            score=0.9
        )
        verdict = aggregate_verdict(ctx)
        assert verdict.decision == Decision.BLOCK
        assert "signature_engine" in verdict.features_triggered

    def test_threat_intel_hit_blocks(self):
        """Threat intel match should block."""
        ctx = self._make_clean_context()
        ctx.threat_intel_result = ThreatIntelResult(
            hit=True,
            source="AlienVault OTX",
            confidence=0.92,
            threat_type="C2 Server"
        )
        verdict = aggregate_verdict(ctx)
        assert verdict.decision == Decision.BLOCK
        assert "threat_intel" in verdict.features_triggered

    def test_high_risk_app_blocks(self):
        """High-risk application (>= 0.7 risk) should block."""
        ctx = self._make_clean_context()
        ctx.app_result = ApplicationResult(
            application="Tor",
            confidence=0.95,
            category="anonymizer",
            risk_level=0.9
        )
        verdict = aggregate_verdict(ctx)
        assert verdict.decision == Decision.BLOCK

    def test_anomaly_detection_blocks(self):
        """Protocol anomaly should block traffic."""
        ctx = self._make_clean_context()
        ctx.anomaly_result = AnomalyResult(
            detected=True,
            protocol="HTTP",
            reason="Abnormal header structure",
            score=0.85
        )
        verdict = aggregate_verdict(ctx)
        assert verdict.decision == Decision.BLOCK
        assert "protocol_anomaly" in verdict.features_triggered

    def test_verdict_details_contain_metadata(self):
        """Verdict details should include inspection metadata."""
        ctx = self._make_clean_context()
        ctx.app_result = ApplicationResult(application="HTTP", confidence=0.99)
        verdict = aggregate_verdict(ctx)
        details = verdict.to_dict()
        assert "details" in details

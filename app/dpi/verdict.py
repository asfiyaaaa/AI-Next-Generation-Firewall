"""
DPI Verdict Models - Simplified Blocking Logic
Block immediately if ANY stage detects malicious content.
"""
from dataclasses import dataclass, field
from typing import Optional, List
from .constants import (
    Decision, Severity, 
    FEATURE_APP_ID, FEATURE_SIGNATURE, FEATURE_IPS, 
    FEATURE_ANOMALY, FEATURE_THREAT_INTEL, FEATURE_TLS
)
from .context import InspectionContext


@dataclass
class DPIVerdict:
    """
    Final DPI verdict.
    
    SIMPLIFIED LOGIC:
    - Block if ANY stage detects malicious content
    - No complex scoring required
    """
    decision: Decision
    reason: str
    confidence: float
    features_triggered: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    details: dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        """Convert verdict to dictionary for API response."""
        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "confidence": round(self.confidence, 3),
            "risk_score": round(self.risk_score, 3),
            "features_triggered": self.features_triggered,
            "details": self.details
        }


def aggregate_verdict(ctx: InspectionContext) -> DPIVerdict:
    """
    Aggregate all stage results into a final DPI verdict.
    
    SIMPLIFIED BLOCKING LOGIC:
    - If ANY stage detects malicious content → BLOCK
    - No cumulative scoring required
    """
    features_triggered: List[str] = []
    reasons: List[str] = []
    should_block = False
    block_reason = ""
    
    # ===========================================
    # CHECK EACH STAGE FOR THREATS
    # ===========================================
    
    # 1. Application Identification - Block high-risk apps (VPN, Tor, C2)
    if ctx.app_result.risk_level >= 0.7:
        should_block = True
        block_reason = f"High-risk application detected: {ctx.app_result.application}"
        features_triggered.append(FEATURE_APP_ID)
        reasons.append(block_reason)
    elif ctx.app_result.risk_level > 0.3:
        features_triggered.append(FEATURE_APP_ID)
        reasons.append(f"Elevated risk application: {ctx.app_result.application}")
    
    # 2. TLS Inspection - Block suspicious TLS
    if ctx.tls_result.suspicious_fingerprint:
        should_block = True
        block_reason = "Malicious TLS fingerprint detected (known malware JA3)"
        features_triggered.append(FEATURE_TLS)
        reasons.append(block_reason)
    elif ctx.tls_result.suspicious_domain:
        should_block = True
        block_reason = f"Suspicious domain in TLS SNI"
        features_triggered.append(FEATURE_TLS)
        reasons.append(block_reason)
    elif ctx.tls_result.cert_issues:
        should_block = True
        block_reason = "TLS certificate validation failed"
        features_triggered.append(FEATURE_TLS)
        reasons.append(block_reason)
    
    # 3. Signature Matching - Block ANY signature match
    if ctx.signature_result.has_matches:
        should_block = True
        top_match = ctx.signature_result.matches[0]
        block_reason = f"Signature matched: {top_match.name} (severity: {top_match.severity.value})"
        features_triggered.append(FEATURE_SIGNATURE)
        reasons.append(block_reason)
    
    # 4. IPS - Block ANY attack detection
    if ctx.ips_result.triggered:
        should_block = True
        block_reason = f"Attack detected: {ctx.ips_result.attack_type} (severity: {ctx.ips_result.severity.value})"
        features_triggered.append(FEATURE_IPS)
        reasons.append(block_reason)
    
    # 5. Protocol Anomaly - Block if anomaly detected
    if ctx.anomaly_result.detected:
        should_block = True
        block_reason = f"Protocol anomaly: {ctx.anomaly_result.reason}"
        features_triggered.append(FEATURE_ANOMALY)
        reasons.append(block_reason)
    
    # 6. Threat Intelligence - Block if threat intel hit
    if ctx.threat_intel_result.hit:
        should_block = True
        block_reason = f"Threat intelligence match: {ctx.threat_intel_result.source} ({ctx.threat_intel_result.threat_type})"
        features_triggered.append(FEATURE_THREAT_INTEL)
        reasons.append(block_reason)
    
    # ===========================================
    # CALCULATE RISK SCORE (for display)
    # ===========================================
    
    risk_score = 0.0
    if ctx.app_result.risk_level > 0:
        risk_score += ctx.app_result.risk_level * 0.15
    if ctx.tls_result.risk_score > 0:
        risk_score += ctx.tls_result.risk_score * 0.10
    if ctx.signature_result.score > 0:
        risk_score += ctx.signature_result.score * 0.25
    if ctx.ips_result.triggered:
        severity_scores = {Severity.LOW: 0.25, Severity.MEDIUM: 0.5, Severity.HIGH: 0.75, Severity.CRITICAL: 1.0}
        risk_score += severity_scores.get(ctx.ips_result.severity, 0.5) * 0.30
    if ctx.anomaly_result.score > 0:
        risk_score += ctx.anomaly_result.score * 0.10
    if ctx.threat_intel_result.hit:
        risk_score += ctx.threat_intel_result.confidence * 0.10
    
    risk_score = min(1.0, risk_score)
    
    # If blocking, ensure risk score is high
    if should_block:
        risk_score = max(risk_score, 0.8)
    
    # ===========================================
    # MAKE DECISION
    # ===========================================
    
    if should_block:
        decision = Decision.BLOCK
        confidence = max(risk_score, 0.85)
        reason = "; ".join(reasons)
    else:
        decision = Decision.ALLOW
        confidence = 1.0 - risk_score
        reason = "No threats detected"
    
    # ===========================================
    # BUILD DETAILS
    # ===========================================
    
    details = {
        "app_identified": ctx.app_result.application,
        "app_confidence": round(ctx.app_result.confidence, 3),
        "threat_count": len(features_triggered),
        "stages_completed": ctx.stages_completed,
        "stages_failed": len(ctx.errors) if ctx.errors else 0,
    }
    
    if ctx.ips_result.triggered:
        details["attack_type"] = ctx.ips_result.attack_type
        details["attack_severity"] = ctx.ips_result.severity.value
    
    if ctx.signature_result.has_matches:
        details["signature_matches"] = [
            {"name": m.name, "severity": m.severity.value}
            for m in ctx.signature_result.matches[:5]
        ]
    
    if ctx.threat_intel_result.hit:
        details["threat_intel_source"] = ctx.threat_intel_result.source
        details["threat_type"] = ctx.threat_intel_result.threat_type
    
    if ctx.errors:
        details["errors"] = ctx.errors
    
    return DPIVerdict(
        decision=decision,
        reason=reason,
        confidence=round(confidence, 3),
        features_triggered=features_triggered,
        risk_score=round(risk_score, 3),
        details=details
    )

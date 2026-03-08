"""
DPI Inspection Context
Holds all data for a single inspection pass through the 8-stage pipeline.
"""
from dataclasses import dataclass, field
from typing import Optional, Any
from .constants import ContentType, Decision, Severity


@dataclass
class TLSMetadata:
    """TLS-specific metadata for inspection."""
    sni: Optional[str] = None
    ja3: Optional[str] = None
    ja3s: Optional[str] = None
    cert_cn: Optional[str] = None
    cert_san: Optional[list[str]] = None
    alpn: Optional[str] = None
    version: Optional[str] = None
    is_decrypted: bool = False


@dataclass
class ConnectionMetadata:
    """Network connection metadata."""
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = "TCP"
    application_hint: Optional[str] = None
    tls_metadata: Optional[TLSMetadata] = None


@dataclass
class ApplicationResult:
    """Result from application identification stage."""
    application: str = "Unknown"
    confidence: float = 0.0
    category: Optional[str] = None
    risk_level: float = 0.0


@dataclass
class SignatureMatch:
    """A single signature match result."""
    id: int
    name: str
    offset: int
    severity: Severity = Severity.MEDIUM
    confidence: float = 1.0


@dataclass
class SignatureResult:
    """Result from signature matching stage."""
    matches: list[SignatureMatch] = field(default_factory=list)
    score: float = 0.0
    
    @property
    def has_matches(self) -> bool:
        return len(self.matches) > 0


@dataclass
class IPSResult:
    """Result from IPS stage."""
    triggered: bool = False
    attack_type: Optional[str] = None
    severity: Severity = Severity.LOW
    confidence: float = 0.0
    details: Optional[str] = None


@dataclass
class TLSInspectionResult:
    """Result from TLS inspection stage."""
    mode: str = "none"  # "decrypted", "metadata_only", "none"
    risk_score: float = 0.0
    suspicious_fingerprint: bool = False
    suspicious_domain: bool = False
    cert_issues: list[str] = field(default_factory=list)


@dataclass
class AnomalyResult:
    """Result from protocol anomaly detection stage."""
    detected: bool = False
    protocol: Optional[str] = None
    reason: Optional[str] = None
    score: float = 0.0
    anomalies: list[str] = field(default_factory=list)


@dataclass
class ThreatIntelResult:
    """Result from threat intelligence stage."""
    hit: bool = False
    source: Optional[str] = None
    confidence: float = 0.0
    indicator_type: Optional[str] = None
    threat_type: Optional[str] = None


@dataclass
class InspectionContext:
    """
    Complete context for a single DPI inspection.
    Passed through all 8 pipeline stages, accumulating results.
    """
    # Input data
    raw_payload: bytes
    content_type_hint: ContentType
    metadata: ConnectionMetadata
    
    # Normalized data (populated by Stage 1)
    normalized_payload: Optional[bytes] = None
    decoded_text: Optional[str] = None
    detected_content_type: Optional[str] = None
    detected_file_type: Optional[str] = None
    
    # Stage results
    app_result: ApplicationResult = field(default_factory=ApplicationResult)
    tls_result: TLSInspectionResult = field(default_factory=TLSInspectionResult)
    signature_result: SignatureResult = field(default_factory=SignatureResult)
    ips_result: IPSResult = field(default_factory=IPSResult)
    anomaly_result: AnomalyResult = field(default_factory=AnomalyResult)
    threat_intel_result: ThreatIntelResult = field(default_factory=ThreatIntelResult)
    
    # Pipeline state
    stages_completed: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    
    def get_inspection_text(self) -> str:
        """Get the best text representation for inspection."""
        if self.decoded_text:
            return self.decoded_text
        if self.normalized_payload:
            try:
                return self.normalized_payload.decode('utf-8', errors='replace')
            except Exception:
                pass
        try:
            return self.raw_payload.decode('utf-8', errors='replace')
        except Exception:
            return ""
    
    def mark_stage_complete(self, stage: str) -> None:
        """Mark a pipeline stage as completed."""
        if stage not in self.stages_completed:
            self.stages_completed.append(stage)
    
    def add_error(self, error: str) -> None:
        """Add an error message."""
        self.errors.append(error)


        










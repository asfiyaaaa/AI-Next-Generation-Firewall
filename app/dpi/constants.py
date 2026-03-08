"""
DPI Core Constants
Enterprise-grade constants for the DPI engine.
"""
from enum import Enum
from typing import Final


class Decision(str, Enum):
    """DPI verdict decisions."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


class Severity(str, Enum):
    """Attack severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ContentType(str, Enum):
    """Content type hints for inspection."""
    TEXT = "text"
    IMAGE = "image"
    VIDEO = "video"
    BINARY = "binary"
    UNKNOWN = "unknown"


class AttackType(str, Enum):
    """Known attack types for IPS."""
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting"
    COMMAND_INJECTION = "Command Injection"
    LDAP_INJECTION = "LDAP Injection"
    TEMPLATE_INJECTION = "Template Injection"
    DESERIALIZATION = "Deserialization Attack"
    RPC_ABUSE = "RPC Abuse"
    PATH_TRAVERSAL = "Path Traversal"
    XXE = "XML External Entity"


class Protocol(str, Enum):
    """Supported protocols."""
    TCP = "TCP"
    UDP = "UDP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    TLS = "TLS"


class DPIStage(str, Enum):
    """DPI pipeline stages (mandatory order)."""
    NORMALIZATION = "normalization"
    APPLICATION_ID = "application_id"
    TLS_INSPECTION = "tls_inspection"
    SIGNATURE_MATCHING = "signature_matching"
    IPS = "ips"
    PROTOCOL_ANOMALY = "protocol_anomaly"
    THREAT_INTEL = "threat_intel"
    VERDICT_AGGREGATION = "verdict_aggregation"


# Safety limits
MAX_PAYLOAD_SIZE: Final[int] = 10 * 1024 * 1024  # 10 MB
MAX_DECODE_DEPTH: Final[int] = 3
MAX_REGEX_TIMEOUT_MS: Final[int] = 100
MIN_BLOCK_CONFIDENCE: Final[float] = 0.75

# Risk score weights
WEIGHT_APP_RISK: Final[float] = 0.15
WEIGHT_SIGNATURE: Final[float] = 0.25
WEIGHT_IPS: Final[float] = 0.30
WEIGHT_ANOMALY: Final[float] = 0.15
WEIGHT_THREAT_INTEL: Final[float] = 0.15

# Feature names for verdict
FEATURE_APP_ID: Final[str] = "app_id"
FEATURE_TLS: Final[str] = "tls_inspection"
FEATURE_SIGNATURE: Final[str] = "signature_engine"
FEATURE_IPS: Final[str] = "ips"
FEATURE_ANOMALY: Final[str] = "protocol_anomaly"
FEATURE_THREAT_INTEL: Final[str] = "threat_intel"

"""
IPS Engine - Stage 5
Semantic attack detection with intent understanding.
"""
import re
import logging
from typing import List, Tuple, Optional
from dataclasses import dataclass

from .context import InspectionContext, IPSResult
from .constants import Severity, AttackType

logger = logging.getLogger(__name__)


@dataclass
class AttackIndicator:
    """Individual attack indicator found in payload."""
    attack_type: AttackType
    severity: Severity
    confidence: float
    detail: str
    offset: int = 0


class SQLInjectionDetector:
    """Semantic SQL injection detection."""
    
    PATTERNS = [
        # High confidence patterns (clear attack intent)
        (r"(?i)union\s+(?:all\s+)?select\s+.+\s+from", 0.95, Severity.HIGH),
        (r"(?i);\s*drop\s+(?:table|database)", 0.98, Severity.CRITICAL),
        (r"(?i);\s*delete\s+from\s+\w+\s*(?:where|;|$)", 0.95, Severity.CRITICAL),
        (r"(?i)'\s*or\s+['\"0-9]=\s*['\"0-9]", 0.9, Severity.HIGH),
        (r"(?i)'\s*or\s+1\s*=\s*1", 0.95, Severity.HIGH),
        (r"(?i)admin'\s*--", 0.9, Severity.HIGH),
        
        # Time-based blind
        (r"(?i)(?:sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(", 0.85, Severity.HIGH),
        
        # Boolean-based
        (r"(?i)'\s*and\s+\d+\s*=\s*\d+", 0.8, Severity.MEDIUM),
        
        # Comment-based
        (r"(?i)'\s*(?:--|#|/\*)", 0.7, Severity.MEDIUM),
        
        # Stacked queries
        (r"(?i);\s*(?:insert|update|alter|create)\s+", 0.9, Severity.HIGH),
    ]
    
    def detect(self, text: str) -> Optional[AttackIndicator]:
        """Detect SQL injection with semantic analysis."""
        for pattern, confidence, severity in self.PATTERNS:
            match = re.search(pattern, text)
            if match:
                return AttackIndicator(
                    attack_type=AttackType.SQL_INJECTION,
                    severity=severity,
                    confidence=confidence,
                    detail=f"Pattern matched at offset {match.start()}",
                    offset=match.start()
                )
        return None


class XSSDetector:
    """Semantic XSS detection."""
    
    PATTERNS = [
        # Script injection
        (r"(?i)<\s*script[^>]*>.*?</\s*script\s*>", 0.95, Severity.HIGH),
        (r"(?i)<\s*script[^>]*>", 0.85, Severity.HIGH),
        
        # Event handlers
        (r"(?i)\bon(?:error|load|click|mouseover|mouseout|focus|blur)\s*=\s*['\"]?[^>]+", 0.9, Severity.HIGH),
        
        # JavaScript URIs
        (r"(?i)(?:href|src)\s*=\s*['\"]?\s*javascript:", 0.95, Severity.HIGH),
        (r"(?i)data:\s*text/html", 0.85, Severity.HIGH),
        
        # SVG/dangerous elements
        (r"(?i)<\s*(?:svg|iframe|embed|object)[^>]*\s+on\w+\s*=", 0.9, Severity.HIGH),
        
        # Expression injection
        (r"(?i)expression\s*\([^)]*\)", 0.85, Severity.MEDIUM),
    ]
    
    # Benign patterns that reduce confidence
    BENIGN_CONTEXT = [
        r"(?i)text/javascript",  # Legitimate MIME type
        r"(?i)application/javascript",
        r"(?i)Content-Type:",  # HTTP header
    ]
    
    def detect(self, text: str) -> Optional[AttackIndicator]:
        """Detect XSS with context awareness."""
        # Check for benign context first
        in_benign_context = any(re.search(p, text) for p in self.BENIGN_CONTEXT)
        
        for pattern, confidence, severity in self.PATTERNS:
            match = re.search(pattern, text)
            if match:
                # Reduce confidence in benign context
                adj_confidence = confidence * 0.7 if in_benign_context else confidence
                
                # Skip if confidence too low
                if adj_confidence < 0.5:
                    continue
                
                return AttackIndicator(
                    attack_type=AttackType.XSS,
                    severity=severity,
                    confidence=adj_confidence,
                    detail=f"XSS pattern at offset {match.start()}",
                    offset=match.start()
                )
        return None


class CommandInjectionDetector:
    """OS command injection detection."""
    
    PATTERNS = [
        # Shell metacharacters with commands
        (r"(?i)[;&|`]\s*(?:cat|ls|dir|whoami|id|uname|hostname|rm|mv|cp|chmod|chown)\b", 0.95, Severity.CRITICAL),
        (r"(?i)\|\s*(?:nc|netcat|curl|wget|bash|sh|cmd|powershell|rm|mv|cp)\b", 0.95, Severity.CRITICAL),
        
        # Backtick command substitution
        (r"`[^`]+(?:whoami|cat|ls|id|rm)[^`]*`", 0.9, Severity.CRITICAL),
        
        # $() substitution
        (r"\$\([^)]+(?:whoami|cat|ls|id|rm)[^)]*\)", 0.9, Severity.CRITICAL),
        
        # Common paths
        (r"(?:/bin/(?:bash|sh|dash)|/etc/passwd|/etc/shadow|/proc/self)", 0.9, Severity.HIGH),
        
        # Reverse shell patterns
        (r"(?i)(?:bash\s+-i|nc\s+-e|rm\s+/tmp/f;mkfifo)", 0.98, Severity.CRITICAL),
        
        # Dangerous commands with arguments (semicolon followed by rm -rf, etc.)
        (r";\s*rm\s+-", 0.95, Severity.CRITICAL),
    ]
    
    def detect(self, text: str) -> Optional[AttackIndicator]:
        """Detect command injection."""
        for pattern, confidence, severity in self.PATTERNS:
            match = re.search(pattern, text)
            if match:
                return AttackIndicator(
                    attack_type=AttackType.COMMAND_INJECTION,
                    severity=severity,
                    confidence=confidence,
                    detail=f"Command injection at offset {match.start()}",
                    offset=match.start()
                )
        return None


class LDAPInjectionDetector:
    """LDAP injection detection."""
    
    PATTERNS = [
        (r"\)\s*\(\s*[&|!]", 0.85, Severity.HIGH),
        (r"\*\s*\)\s*\(", 0.8, Severity.HIGH),
        (r"\x00", 0.7, Severity.MEDIUM),  # Null byte
        (r"\)\s*\(\|", 0.85, Severity.HIGH),
    ]
    
    def detect(self, text: str) -> Optional[AttackIndicator]:
        """Detect LDAP injection."""
        for pattern, confidence, severity in self.PATTERNS:
            match = re.search(pattern, text)
            if match:
                return AttackIndicator(
                    attack_type=AttackType.LDAP_INJECTION,
                    severity=severity,
                    confidence=confidence,
                    detail="LDAP filter manipulation detected",
                    offset=match.start()
                )
        return None


class TemplateInjectionDetector:
    """Server-side template injection detection."""
    
    PATTERNS = [
        # Jinja2/Twig
        (r"\{\{\s*(?:config|self|request|cycler|joiner|namespace)\s*\}\}", 0.9, Severity.HIGH),
        (r"\{\{[^}]*\.__class__\.__mro__", 0.95, Severity.CRITICAL),
        (r"\{%\s*(?:import|extends|include)\s+", 0.8, Severity.HIGH),
        
        # Freemarker
        (r"<#(?:assign|include|import)\s+", 0.85, Severity.HIGH),
        
        # Expression language
        (r"\$\{[^}]*(?:Runtime|ProcessBuilder|exec\()", 0.95, Severity.CRITICAL),
        
        # Common payloads
        (r"\{\{7\*7\}\}", 0.7, Severity.MEDIUM),  # Detection probe
        (r"\${7\*7}", 0.7, Severity.MEDIUM),
    ]
    
    def detect(self, text: str) -> Optional[AttackIndicator]:
        """Detect template injection."""
        for pattern, confidence, severity in self.PATTERNS:
            match = re.search(pattern, text)
            if match:
                return AttackIndicator(
                    attack_type=AttackType.TEMPLATE_INJECTION,
                    severity=severity,
                    confidence=confidence,
                    detail="Template injection pattern detected",
                    offset=match.start()
                )
        return None


class DeserializationDetector:
    """Deserialization attack detection."""
    
    def detect(self, text: str, raw_bytes: bytes = None) -> Optional[AttackIndicator]:
        """Detect deserialization attacks."""
        # Java serialization magic bytes
        if raw_bytes:
            if raw_bytes.startswith(b'\xac\xed\x00\x05'):
                return AttackIndicator(
                    attack_type=AttackType.DESERIALIZATION,
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    detail="Java serialized object detected"
                )
        
        # Base64 encoded Java object
        if 'rO0AB' in text:
            return AttackIndicator(
                attack_type=AttackType.DESERIALIZATION,
                severity=Severity.CRITICAL,
                confidence=0.9,
                detail="Base64 encoded Java object detected"
            )
        
        # PHP object injection
        php_pattern = r'O:\d+:"[^"]+":|\ba:\d+:\{[^}]*s:\d+:'
        if re.search(php_pattern, text):
            return AttackIndicator(
                attack_type=AttackType.DESERIALIZATION,
                severity=Severity.CRITICAL,
                confidence=0.85,
                detail="PHP serialized object detected"
            )
        
        # Python pickle
        if raw_bytes:
            if b'__reduce__' in raw_bytes or raw_bytes.startswith(b'\x80\x04\x95'):
                return AttackIndicator(
                    attack_type=AttackType.DESERIALIZATION,
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    detail="Python pickle detected"
                )
        
        return None


class RPCAbuseDetector:
    """RPC abuse and dangerous method detection."""
    
    DANGEROUS_METHODS = [
        # Java RMI
        (r"(?i)java\.lang\.Runtime", 0.9, Severity.CRITICAL),
        (r"(?i)ProcessBuilder", 0.85, Severity.CRITICAL),
        
        # gRPC reflection
        (r"(?i)grpc\.reflection", 0.6, Severity.MEDIUM),
        (r"(?i)ServerReflection", 0.6, Severity.MEDIUM),
        
        # Dangerous JSON-RPC methods
        (r'"method"\s*:\s*"(?:system|exec|eval|shell)"', 0.9, Severity.CRITICAL),
        
        # XML-RPC
        (r"<methodName>(?:system\.|os\.|exec)", 0.9, Severity.CRITICAL),
    ]
    
    def detect(self, text: str) -> Optional[AttackIndicator]:
        """Detect RPC abuse."""
        for pattern, confidence, severity in self.DANGEROUS_METHODS:
            match = re.search(pattern, text)
            if match:
                return AttackIndicator(
                    attack_type=AttackType.RPC_ABUSE,
                    severity=severity,
                    confidence=confidence,
                    detail="Dangerous RPC method detected",
                    offset=match.start()
                )
        return None


class IPSEngine:
    """
    Stage 5: Intrusion Prevention System
    
    Semantic attack detection that:
    - Understands attack intent
    - Assigns severity levels
    - Avoids blocking benign edge cases
    - Provides detailed explanations
    """
    
    def __init__(self):
        self._detectors = [
            SQLInjectionDetector(),
            XSSDetector(),
            CommandInjectionDetector(),
            LDAPInjectionDetector(),
            TemplateInjectionDetector(),
            DeserializationDetector(),
            RPCAbuseDetector(),
        ]
    
    def detect(self, ctx: InspectionContext) -> None:
        """
        Run all IPS detectors on context.
        Updates ctx.ips_result with findings.
        """
        text = ctx.get_inspection_text()
        raw_bytes = ctx.normalized_payload or ctx.raw_payload
        
        all_indicators: List[AttackIndicator] = []
        
        # Run each detector
        for detector in self._detectors:
            try:
                if isinstance(detector, DeserializationDetector):
                    result = detector.detect(text, raw_bytes)
                else:
                    result = detector.detect(text)
                
                if result:
                    all_indicators.append(result)
            except Exception as e:
                logger.debug(f"Detector error: {e}")
        
        if all_indicators:
            # Select highest severity indicator
            all_indicators.sort(
                key=lambda x: (
                    list(Severity).index(x.severity),
                    -x.confidence
                ),
                reverse=True
            )
            
            primary = all_indicators[0]
            
            ctx.ips_result = IPSResult(
                triggered=True,
                attack_type=primary.attack_type.value,
                severity=primary.severity,
                confidence=primary.confidence,
                details=primary.detail
            )
            
            # logger.warning(
            #     f"IPS triggered: {primary.attack_type.value} "
            #     f"(severity={primary.severity.value}, confidence={primary.confidence:.2f})"
            # )
        else:
            ctx.ips_result = IPSResult(triggered=False)

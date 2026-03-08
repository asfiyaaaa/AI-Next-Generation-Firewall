"""
Anomaly Engine - Stage 6
Protocol-aware anomaly detection.
"""
import re
import logging
from typing import List, Optional
from dataclasses import dataclass

from .context import InspectionContext, AnomalyResult

logger = logging.getLogger(__name__)


@dataclass
class Anomaly:
    """Detected protocol anomaly."""
    protocol: str
    reason: str
    score: float


class HTTPAnomalyDetector:
    """HTTP protocol anomaly detection."""
    
    VALID_METHODS = {'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT'}
    MAX_HEADER_SIZE = 8192
    MAX_URI_LENGTH = 2048
    
    def detect(self, text: str) -> List[Anomaly]:
        """Detect HTTP-specific anomalies."""
        anomalies: List[Anomaly] = []

        
        # Check for HTTP request/response
        http_match = re.match(r'(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\s+(\S+)\s+HTTP/(\d\.\d)', text)
        if not http_match:
            http_response = re.match(r'HTTP/(\d\.\d)\s+(\d{3})', text)
            if not http_response:
                return anomalies  # Not HTTP
        
        # Check for invalid HTTP method
        if http_match:
            method = http_match.group(1)
            uri = http_match.group(2)
            
            # Invalid method
            if method.upper() not in self.VALID_METHODS:
                anomalies.append(Anomaly(
                    protocol="HTTP",
                    reason=f"Invalid HTTP method: {method}",
                    score=0.7
                ))
            
            # URI too long
            if len(uri) > self.MAX_URI_LENGTH:
                anomalies.append(Anomaly(
                    protocol="HTTP",
                    reason=f"Oversized URI: {len(uri)} bytes",
                    score=0.5
                ))
        
        # Header smuggling detection (CL.TE / TE.CL)
        if 'Transfer-Encoding' in text and 'Content-Length' in text:
            anomalies.append(Anomaly(
                protocol="HTTP",
                reason="Potential header smuggling: both Transfer-Encoding and Content-Length present",
                score=0.8
            ))
        
        # Chunked transfer encoding abuse
        te_match = re.search(r'Transfer-Encoding:\s*([^\r\n]+)', text, re.IGNORECASE)
        if te_match:
            te_value = te_match.group(1).lower()
            if 'chunked' in te_value and te_value != 'chunked':
                anomalies.append(Anomaly(
                    protocol="HTTP",
                    reason=f"Suspicious Transfer-Encoding: {te_value}",
                    score=0.7
                ))
        
        # Malformed headers (no colon)
        header_lines = re.findall(r'\r?\n([^\r\n:]+)\r?\n', text)
        for header in header_lines:
            if header and not header.startswith(' ') and len(header) > 2:
                if not re.match(r'^[\w-]+$', header):  # Not a continuation
                    anomalies.append(Anomaly(
                        protocol="HTTP",
                        reason=f"Malformed header line: {header[:30]}",
                        score=0.6
                    ))
        
        # Null bytes in headers
        if '\x00' in text.split('\r\n\r\n')[0] if '\r\n\r\n' in text else '\x00' in text[:500]:
            anomalies.append(Anomaly(
                protocol="HTTP",
                reason="Null byte in HTTP headers",
                score=0.8
            ))
        
        # Oversized headers
        header_section = text.split('\r\n\r\n')[0] if '\r\n\r\n' in text else text[:2000]
        if len(header_section) > self.MAX_HEADER_SIZE:
            anomalies.append(Anomaly(
                protocol="HTTP",
                reason=f"Oversized headers: {len(header_section)} bytes",
                score=0.5
            ))
        
        return anomalies


class DNSAnomalyDetector:
    """DNS protocol anomaly detection."""
    
    def detect(self, text: str, raw_bytes: bytes = None) -> List[Anomaly]:
        """Detect DNS-specific anomalies."""
        anomalies: List[Anomaly] = []
        
        # DNS tunneling indicators
        # Long subdomain labels
        dns_pattern = r'([a-z0-9]{30,})\.(?:[a-z0-9-]+\.)*[a-z]{2,}'
        if re.search(dns_pattern, text, re.IGNORECASE):
            anomalies.append(Anomaly(
                protocol="DNS",
                reason="Possible DNS tunneling: very long subdomain",
                score=0.7
            ))
        
        # High entropy in DNS query
        if raw_bytes:
            from .safety import calculate_entropy
            entropy = calculate_entropy(raw_bytes[:100])
            if entropy > 5.5:  # High entropy suggests encoding
                anomalies.append(Anomaly(
                    protocol="DNS",
                    reason=f"High entropy DNS query ({entropy:.2f})",
                    score=0.6
                ))
        
        # TXT record with base64-like content
        if 'TXT' in text.upper():
            b64_pattern = r'[A-Za-z0-9+/]{50,}={0,2}'
            if re.search(b64_pattern, text):
                anomalies.append(Anomaly(
                    protocol="DNS",
                    reason="DNS TXT record with Base64-like content",
                    score=0.5
                ))
        
        return anomalies


class RPCAnomalyDetector:
    """RPC protocol anomaly detection."""
    
    def detect(self, text: str) -> List[Anomaly]:
        """Detect RPC-specific anomalies."""
        anomalies: List[Anomaly] = []
        
        # JSON-RPC anomalies
        if '"jsonrpc"' in text:
            # Missing required fields
            if '"method"' not in text:
                anomalies.append(Anomaly(
                    protocol="JSON-RPC",
                    reason="JSON-RPC request missing 'method' field",
                    score=0.5
                ))
            
            # Suspicious batch size
            batch_count = text.count('"jsonrpc"')
            if batch_count > 100:
                anomalies.append(Anomaly(
                    protocol="JSON-RPC",
                    reason=f"Oversized JSON-RPC batch: {batch_count} requests",
                    score=0.6
                ))
        
        # gRPC anomalies
        if 'grpc' in text.lower():
            # Reflection abuse
            if 'ServerReflection' in text or 'grpc.reflection' in text:
                anomalies.append(Anomaly(
                    protocol="gRPC",
                    reason="gRPC reflection service access",
                    score=0.4
                ))
        
        return anomalies


class GenericAnomalyDetector:
    """Generic protocol-agnostic anomaly detection."""
    
    def detect(self, text: str, raw_bytes: bytes = None) -> List[Anomaly]:
        """Detect generic anomalies."""
        anomalies: List[Anomaly] = []
        
        # Null byte injection
        if '\x00' in text:
            anomalies.append(Anomaly(
                protocol="Generic",
                reason="Null byte detected in payload",
                score=0.5
            ))
        
        # Control characters (excluding common ones)
        control_chars = sum(1 for c in text if ord(c) < 32 and c not in '\r\n\t')
        if control_chars > 10:
            anomalies.append(Anomaly(
                protocol="Generic",
                reason=f"Excessive control characters: {control_chars}",
                score=0.4
            ))
        
        # Binary in text context
        if raw_bytes:
            non_printable = sum(1 for b in raw_bytes[:500] if b < 32 and b not in (9, 10, 13))
            ratio = non_printable / min(len(raw_bytes), 500)
            if 0.1 < ratio < 0.3:  # Mixed binary/text
                anomalies.append(Anomaly(
                    protocol="Generic",
                    reason="Mixed binary and text content",
                    score=0.3
                ))
        
        return anomalies


class AnomalyEngine:
    """
    Stage 6: Protocol Anomaly Detection
    
    Validates application-layer protocol behavior:
    - Malformed requests
    - Header smuggling
    - Protocol misuse
    - DNS tunneling
    - Abnormal field sizes
    """
    
    def __init__(self):
        self._http_detector = HTTPAnomalyDetector()
        self._dns_detector = DNSAnomalyDetector()
        self._rpc_detector = RPCAnomalyDetector()
        self._generic_detector = GenericAnomalyDetector()
    
    def detect(self, ctx: InspectionContext) -> None:
        """
        Run all anomaly detectors.
        Updates ctx.anomaly_result with findings.
        """
        text = ctx.get_inspection_text()
        raw_bytes = ctx.normalized_payload or ctx.raw_payload
        
        all_anomalies: List[Anomaly] = []
        
        # Run detectors
        all_anomalies.extend(self._http_detector.detect(text))
        all_anomalies.extend(self._dns_detector.detect(text, raw_bytes))
        all_anomalies.extend(self._rpc_detector.detect(text))
        all_anomalies.extend(self._generic_detector.detect(text, raw_bytes))
        
        if all_anomalies:
            # Sort by score
            all_anomalies.sort(key=lambda x: x.score, reverse=True)
            primary = all_anomalies[0]
            
            # Aggregate score (capped at 1.0)
            total_score = min(1.0, sum(a.score for a in all_anomalies) / 2)
            
            ctx.anomaly_result = AnomalyResult(
                detected=True,
                protocol=primary.protocol,
                reason=primary.reason,
                score=total_score,
                anomalies=[a.reason for a in all_anomalies[:5]]  # Top 5
            )
            
            # logger.info(
            #     f"Anomalies detected: {len(all_anomalies)} "
            #     f"(primary: {primary.protocol} - {primary.reason})"
            # )
        else:
            ctx.anomaly_result = AnomalyResult(detected=False)



























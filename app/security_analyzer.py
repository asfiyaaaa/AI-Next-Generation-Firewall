"""
Phase 3 Inline Security Analyzer

Fully automated, in-process security analysis for reassembled TCP streams.
NO HTTP APIs - all analysis runs directly in the pipeline.

Features:
- Automatic URL filtering (blocklist-based)
- Automatic malware detection (ML model)
- Automatic content filtering (pattern matching)
- Returns ALLOW/BLOCK verdict for each stream

This integrates directly with the TCP Reassembly module.
"""
import logging
import re
import hashlib
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Set
from enum import Enum
import json

try:
    # Try to import backend database for logging results to dashboard
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from phase_3.backend.database import log_stream_analysis
except ImportError:
    log_stream_analysis = None

# HTTP client for cross-process packet broadcasting
import requests
PACKET_INGEST_URL = "http://localhost:8000/api/packets/ingest"

logger = logging.getLogger(__name__)


class SecurityVerdict(Enum):
    """Security analysis verdict."""
    ALLOW = "allow"
    BLOCK = "block"
    WARN = "warn"


@dataclass
class ThreatInfo:
    """Information about a detected threat."""
    threat_type: str  # "malware", "blocked_url", "blocked_content", "suspicious"
    severity: str     # "critical", "high", "medium", "low"
    description: str
    confidence: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisResult:
    """Result of stream security analysis."""
    verdict: SecurityVerdict
    threats: List[ThreatInfo] = field(default_factory=list)
    analyzed_size: int = 0
    content_type: str = "unknown"
    urls_found: List[str] = field(default_factory=list)
    
    @property
    def is_blocked(self) -> bool:
        return self.verdict == SecurityVerdict.BLOCK
    
    @property 
    def threat_count(self) -> int:
        return len(self.threats)


class InlineSecurityAnalyzer:
    """
    Fully automated inline security analyzer.
    
    Runs entirely in-process - no external APIs required.
    Analyzes reassembled streams and returns ALLOW/BLOCK verdict.
    """
    
    # Known malicious domains (blocklist)
    BLOCKED_DOMAINS: Set[str] = {
        # Malware/Phishing
        "malware.com", "phishing.com", "evil.com", "badsite.org",
        "virusdownload.net", "ransomware.xyz", "cryptolocker.info",
        # Adult content
        "pornhub.com", "xvideos.com", "xnxx.com", "redtube.com",
        # Social media (often blocked in enterprise)
        # "facebook.com", "twitter.com", "instagram.com",  # Uncomment to block
        # Gambling
        "poker.com", "casino.com", "bet365.com", "pokerstars.com",
        # Known threat actors
        "cobaltstrike.com", "mimikatz.net",
    }
    
    # Suspicious URL patterns
    SUSPICIOUS_PATTERNS = [
        r'\.exe$', r'\.dll$', r'\.scr$', r'\.bat$', r'\.cmd$', r'\.ps1$',
        r'malware', r'virus', r'trojan', r'ransomware', r'keylogger',
        r'crack', r'keygen', r'warez', r'torrent',
        r'admin\.php', r'shell\.php', r'c99\.php', r'r57\.php',
    ]
    
    # Malicious content signatures (simple byte patterns)
    MALICIOUS_SIGNATURES = [
        # PowerShell encoded commands
        (b'powershell', b'-encodedcommand'),
        (b'powershell', b'-enc '),
        (b'powershell', b'bypass'),
        # Common malware strings
        (b'mimikatz',),
        (b'cobalt',),
        (b'metasploit',),
        (b'meterpreter',),
        # Ransomware indicators
        (b'your files have been encrypted',),
        (b'pay bitcoin',),
        (b'decrypt',),
        # Shell commands
        (b'/bin/bash',),
        (b'cmd.exe /c',),
        (b'nc -e',),  # Netcat reverse shell
    ]
    
    # Blocked file extensions
    BLOCKED_EXTENSIONS = {'.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', 
                          '.vbs', '.js', '.hta', '.jar', '.msi'}
    
    def __init__(self, 
                 enable_url_filter: bool = True,
                 enable_malware_detection: bool = True,
                 enable_content_filter: bool = True,
                 custom_blocklist: Optional[Set[str]] = None,
                 ml_model_path: Optional[str] = None):
        """
        Initialize inline security analyzer.
        
        Args:
            enable_url_filter: Enable URL/domain filtering
            enable_malware_detection: Enable malware pattern detection
            enable_content_filter: Enable content pattern filtering
            custom_blocklist: Additional domains to block
            ml_model_path: Path to ML model for PE file analysis (optional)
        """
        self.enable_url_filter = enable_url_filter
        self.enable_malware_detection = enable_malware_detection
        self.enable_content_filter = enable_content_filter
        
        # Merge custom blocklist
        self.blocked_domains = self.BLOCKED_DOMAINS.copy()
        if custom_blocklist:
            self.blocked_domains.update(custom_blocklist)
        
        # Try to load ML model for PE analysis
        self.ml_model = None
        self.feature_columns = None
        if ml_model_path:
            self._load_ml_model(ml_model_path)
        else:
            # Try default path
            self._load_ml_model("phase-3/ransomware_rf_model_new.pkl")
        
        # Statistics
        self.stats = {
            "streams_analyzed": 0,
            "threats_detected": 0,
            "blocked": 0,
            "allowed": 0,
            "urls_checked": 0,
            "files_analyzed": 0,
            "malware_detected": 0,
            "blocked_urls": 0
        }
        
        logger.info(f"InlineSecurityAnalyzer initialized: URL={enable_url_filter}, "
                    f"Malware={enable_malware_detection}, Content={enable_content_filter}, "
                    f"ML Model={'loaded' if self.ml_model else 'not loaded'}")
    
    def _load_ml_model(self, model_path: str):
        """Load ML model for PE file analysis."""
        try:
            import pickle
            path = Path(model_path)
            if path.exists():
                with open(path, 'rb') as f:
                    self.ml_model = pickle.load(f)
                    
                # Try to load feature columns
                feature_path = path.parent / "model_features.pkl"
                if feature_path.exists():
                    with open(feature_path, 'rb') as f:
                        self.feature_columns = pickle.load(f)
                        
                logger.info(f"ML model loaded from {model_path}")
            else:
                logger.debug(f"ML model not found at {model_path}")
        except Exception as e:
            logger.debug(f"Could not load ML model: {e}")
    
    def analyze(self, data: bytes, 
                src_ip: str = "", dst_ip: str = "",
                src_port: int = 0, dst_port: int = 0,
                stream_id: str = "") -> AnalysisResult:
        """
        Analyze stream data for security threats.
        
        This is the main entry point for automated analysis.
        
        Args:
            data: Raw stream data bytes
            src_ip: Source IP address
            dst_ip: Destination IP address
            src_port: Source port
            dst_port: Destination port
            stream_id: Optional stream identifier
            
        Returns:
            AnalysisResult with verdict (ALLOW/BLOCK) and threat details
        """
        self.stats["streams_analyzed"] += 1
        
        result = AnalysisResult(
            verdict=SecurityVerdict.ALLOW,
            analyzed_size=len(data)
        )
        
        if not data:
            return result
        
        # Detect content type
        result.content_type = self._detect_content_type(data)
        
        # === URL/Domain Filtering ===
        if self.enable_url_filter:
            url_threats = self._analyze_urls(data, dst_ip, dst_port)
            result.threats.extend(url_threats)
            result.urls_found = self._extract_all_urls(data)
        
        # === Malware Detection ===
        if self.enable_malware_detection:
            malware_threats = self._analyze_malware(data, result.content_type)
            result.threats.extend(malware_threats)
        
        # === Content Filtering ===
        if self.enable_content_filter:
            content_threats = self._analyze_content(data)
            result.threats.extend(content_threats)
        
        # === Determine Final Verdict ===
        if any(t.severity in ("critical", "high") for t in result.threats):
            result.verdict = SecurityVerdict.BLOCK
            self.stats["blocked"] += 1
        elif result.threats:
            result.verdict = SecurityVerdict.WARN
            self.stats["allowed"] += 1  # Warnings still allowed
        else:
            self.stats["allowed"] += 1
        
        if result.threats:
            self.stats["threats_detected"] += len(result.threats)
            
        # Log blocked traffic
        if result.is_blocked:
            threat_desc = "; ".join(t.description for t in result.threats[:3])
            logger.warning(
                f"[BLOCKED] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | "
                f"Threats: {result.threat_count} | {threat_desc}"
            )
        
        return result
    
    def _detect_content_type(self, data: bytes) -> str:
        """Detect content type from data."""
        if not data:
            return "unknown"
        
        # HTTP
        if data[:4] in (b'GET ', b'POST', b'PUT ', b'HEAD'):
            return "http_request"
        if data[:5] == b'HTTP/':
            return "http_response"
        
        # Files
        if data[:2] == b'MZ':
            return "pe_executable"
        if data[:4] == b'%PDF':
            return "pdf"
        if data[:2] == b'PK':
            return "zip_archive"
        if data[:3] == b'Rar':
            return "rar_archive"
        if data[:4] == b'\x7fELF':
            return "elf_executable"
        
        # Check if mostly text
        try:
            sample = data[:500].decode('utf-8', errors='strict')
            return "text"
        except:
            return "binary"
    
    def _extract_all_urls(self, data: bytes) -> List[str]:
        """Extract all URLs from data."""
        urls = []
        try:
            text = data.decode('utf-8', errors='ignore')
            
            # HTTP request line
            match = re.search(r'^(GET|POST|PUT|DELETE|HEAD)\s+(\S+)\s+HTTP', text, re.MULTILINE)
            if match:
                path = match.group(2)
                host_match = re.search(r'Host:\s*(\S+)', text, re.IGNORECASE)
                if host_match:
                    urls.append(f"http://{host_match.group(1)}{path}")
            
            # URLs in content
            url_pattern = r'https?://[^\s<>"\']+' 
            urls.extend(re.findall(url_pattern, text))
            
        except:
            pass
        
        return list(set(urls))
    
    def _extract_domain(self, url_or_host: str) -> str:
        """Extract domain from URL or hostname."""
        domain = url_or_host.lower()
        
        # Remove protocol
        if '://' in domain:
            domain = domain.split('://')[1]
        
        # Remove path
        domain = domain.split('/')[0]
        
        # Remove port
        domain = domain.split(':')[0]
        
        return domain
    
    def _analyze_urls(self, data: bytes, dst_ip: str, dst_port: int) -> List[ThreatInfo]:
        """Analyze URLs in data for threats."""
        threats = []
        
        try:
            text = data.decode('utf-8', errors='ignore')
            
            # Extract Host header from HTTP
            host_match = re.search(r'Host:\s*(\S+)', text, re.IGNORECASE)
            if host_match:
                host = host_match.group(1).lower()
                domain = self._extract_domain(host)
                self.stats["urls_checked"] += 1
                
                # Check against blocklist
                if domain in self.blocked_domains:
                    self.stats["blocked_urls"] += 1
                    threats.append(ThreatInfo(
                        threat_type="blocked_url",
                        severity="high",
                        description=f"Blocked domain: {domain}",
                        confidence=100.0,
                        details={"domain": domain, "host": host}
                    ))
                
                # Check pattern matches
                for pattern in self.SUSPICIOUS_PATTERNS:
                    if re.search(pattern, host, re.IGNORECASE):
                        threats.append(ThreatInfo(
                            threat_type="suspicious_url",
                            severity="medium",
                            description=f"Suspicious URL pattern: {pattern}",
                            confidence=70.0,
                            details={"host": host, "pattern": pattern}
                        ))
                        break
            
            # Check URLs in content
            urls = re.findall(r'https?://[^\s<>"\']+', text)
            for url in urls[:10]:  # Limit
                domain = self._extract_domain(url)
                
                if domain in self.blocked_domains:
                    self.stats["blocked_urls"] += 1
                    threats.append(ThreatInfo(
                        threat_type="blocked_url",
                        severity="high",
                        description=f"Blocked URL: {url[:50]}",
                        confidence=100.0,
                        details={"url": url, "domain": domain}
                    ))
                    
        except Exception as e:
            logger.debug(f"URL analysis error: {e}")
        
        return threats
    
    def _analyze_malware(self, data: bytes, content_type: str) -> List[ThreatInfo]:
        """Analyze data for malware indicators."""
        threats = []
        
        # PE file analysis
        if content_type == "pe_executable" or data[:2] == b'MZ':
            self.stats["files_analyzed"] += 1
            
            # Use ML model if available
            if self.ml_model:
                ml_result = self._analyze_pe_ml(data)
                if ml_result:
                    threats.append(ml_result)
            
            # Fallback: Pattern-based detection
            pattern_threats = self._detect_malware_patterns(data)
            threats.extend(pattern_threats)
            
            # Check for suspicious characteristics
            if self._has_suspicious_pe_characteristics(data):
                threats.append(ThreatInfo(
                    threat_type="suspicious_pe",
                    severity="medium",
                    description="PE file with suspicious characteristics",
                    confidence=60.0
                ))
        
        # Check for malicious script patterns
        if content_type in ("text", "http_response"):
            script_threats = self._detect_malicious_scripts(data)
            threats.extend(script_threats)
        
        return threats
    
    def _analyze_pe_ml(self, pe_data: bytes) -> Optional[ThreatInfo]:
        """Analyze PE file using ML model."""
        try:
            # Import PE feature extractor
            import sys
            sys.path.insert(0, str(Path(__file__).parent.parent / "phase-3" / "backend"))
            from feature_extractor import extract_features_from_bytes, FEATURE_COLUMNS
            
            import pandas as pd
            
            features = extract_features_from_bytes(pe_data)
            if features is None:
                return None
            
            feature_vector = [features.get(col, 0) for col in FEATURE_COLUMNS]
            df = pd.DataFrame([feature_vector], columns=FEATURE_COLUMNS)
            
            prediction = self.ml_model.predict(df)[0]
            confidence = 0.0
            if hasattr(self.ml_model, 'predict_proba'):
                confidence = float(max(self.ml_model.predict_proba(df)[0])) * 100
            
            is_malicious = prediction == 0  # 0 = malware in the model
            
            if is_malicious:
                self.stats["malware_detected"] += 1
                return ThreatInfo(
                    threat_type="malware",
                    severity="critical",
                    description=f"ML detected ransomware/malware ({confidence:.1f}% confidence)",
                    confidence=confidence,
                    details={"prediction": "malware", "ml_confidence": confidence}
                )
                
        except Exception as e:
            logger.debug(f"ML analysis failed: {e}")
        
        return None
    
    def _detect_malware_patterns(self, data: bytes) -> List[ThreatInfo]:
        """Detect malware using signature patterns."""
        threats = []
        data_lower = data.lower()
        
        for sig in self.MALICIOUS_SIGNATURES:
            if all(pattern in data_lower for pattern in sig):
                pattern_str = b' + '.join(sig).decode('utf-8', errors='ignore')
                threats.append(ThreatInfo(
                    threat_type="malware_signature",
                    severity="high",
                    description=f"Malicious pattern detected: {pattern_str[:50]}",
                    confidence=85.0,
                    details={"pattern": pattern_str}
                ))
                break  # One hit is enough
        
        return threats
    
    def _has_suspicious_pe_characteristics(self, pe_data: bytes) -> bool:
        """Check for suspicious PE characteristics."""
        # Very small PE file
        if len(pe_data) < 1024:
            return True
        
        # Check for high entropy (packed/encrypted)
        try:
            import math
            byte_counts = [0] * 256
            for byte in pe_data[:4096]:
                byte_counts[byte] += 1
            
            entropy = 0.0
            length = min(len(pe_data), 4096)
            for count in byte_counts:
                if count > 0:
                    p = count / length
                    entropy -= p * math.log2(p)
            
            # High entropy suggests packing/encryption
            if entropy > 7.5:
                return True
        except:
            pass
        
        return False
    
    def _detect_malicious_scripts(self, data: bytes) -> List[ThreatInfo]:
        """Detect malicious script patterns."""
        threats = []
        
        try:
            text = data.decode('utf-8', errors='ignore').lower()
            
            # PowerShell obfuscation
            if 'powershell' in text:
                if any(x in text for x in ['-enc', '-encoded', 'bypass', 'hidden']):
                    threats.append(ThreatInfo(
                        threat_type="malicious_script",
                        severity="high",
                        description="Obfuscated PowerShell command detected",
                        confidence=90.0
                    ))
            
            # Base64 encoded commands  
            if re.search(r'[A-Za-z0-9+/]{50,}={0,2}', text):
                # Long base64 string might be encoded payload
                if any(x in text for x in ['exec', 'eval', 'invoke', 'shell']):
                    threats.append(ThreatInfo(
                        threat_type="encoded_payload",
                        severity="medium",
                        description="Possible encoded payload detected",
                        confidence=60.0
                    ))
            
        except:
            pass
        
        return threats
    
    def _analyze_content(self, data: bytes) -> List[ThreatInfo]:
        """Analyze content for policy violations."""
        threats = []
        
        # Check for blocked file types in HTTP response
        try:
            text = data.decode('utf-8', errors='ignore')
            
            # Check Content-Disposition for filename
            match = re.search(r'filename[*]?=["\'"]?([^"\'\s;]+)', text, re.IGNORECASE)
            if match:
                filename = match.group(1).lower()
                ext = '.' + filename.split('.')[-1] if '.' in filename else ''
                
                if ext in self.BLOCKED_EXTENSIONS:
                    threats.append(ThreatInfo(
                        threat_type="blocked_file_type",
                        severity="high",
                        description=f"Blocked file type: {ext}",
                        confidence=100.0,
                        details={"filename": filename, "extension": ext}
                    ))
                    
        except:
            pass
        
        return threats
    
    def get_stats(self) -> Dict[str, Any]:
        """Get analyzer statistics."""
        return dict(self.stats)


# === Callback wrapper for TCP Reassembly ===
class AutomatedSecurityCallback:
    """
    Callback wrapper that automatically analyzes reassembled streams.
    
    Use this as the phase3_callback for TCPReassembler.
    """
    
    def __init__(self, analyzer: Optional[InlineSecurityAnalyzer] = None):
        self.analyzer = analyzer or InlineSecurityAnalyzer()
        self.blocked_streams: List[str] = []
        self.analysis_history: List[AnalysisResult] = []
        
    def __call__(self, stream) -> None:
        """
        Process reassembled stream.
        
        This is called by TCPReassembler when data is ready.
        """
        result = self.analyzer.analyze(
            data=stream.data,
            src_ip=stream.src_ip,
            dst_ip=stream.dst_ip,
            src_port=stream.src_port,
            dst_port=stream.dst_port,
            stream_id=stream.stream_id
        )
        
        # Store result
        self.analysis_history.append(result)
        if len(self.analysis_history) > 1000:
            self.analysis_history = self.analysis_history[-500:]
        
        if result.is_blocked:
            self.blocked_streams.append(stream.stream_id)
            
        # Log to shared database for dashboard visibility
        if log_stream_analysis:
            try:
                # Format threats for database JSON field
                threat_list = []
                for t in result.threats:
                    threat_list.append({
                        "type": t.threat_type,
                        "severity": t.severity,
                        "description": t.description,
                        "details": t.details
                    })
                
                log_stream_analysis(
                    stream_id=stream.stream_id,
                    src_ip=stream.src_ip,
                    dst_ip=stream.dst_ip,
                    src_port=stream.src_port,
                    dst_port=stream.dst_port,
                    data_size=len(stream.data),
                    verdict=result.verdict.value,
                    threats_found=len(result.threats),
                    analyses=threat_list
                )
            except Exception as e:
                logger.debug(f"Failed to log to database: {e}")
        
        # Broadcast to WebSocket clients for live UI via HTTP POST
        try:
            requests.post(PACKET_INGEST_URL, json={
                "src_ip": stream.src_ip or "",
                "dst_ip": stream.dst_ip or "",
                "src_port": stream.src_port or 0,
                "dst_port": stream.dst_port or 0,
                "protocol": "TCP",
                "size": len(stream.data),
                "verdict": result.verdict.value.upper(),
                "threat_type": threat_list[0]["type"] if threat_list else "None"
            }, timeout=0.5)
        except Exception as e:
            pass  # Non-blocking, best-effort broadcast
            
    def get_stats(self) -> Dict[str, Any]:
        """Get combined statistics."""
        return {
            **self.analyzer.get_stats(),
            "recent_blocked": len(self.blocked_streams),
            "history_size": len(self.analysis_history)
        }


# Convenience function
def create_security_analyzer(
    enable_all: bool = True,
    custom_blocklist: Optional[Set[str]] = None
) -> AutomatedSecurityCallback:
    """
    Create an automated security analyzer callback.
    
    Usage:
        from app.security_analyzer import create_security_analyzer
        
        analyzer = create_security_analyzer()
        reassembler = TCPReassembler(phase3_callback=analyzer)
    """
    analyzer = InlineSecurityAnalyzer(
        enable_url_filter=enable_all,
        enable_malware_detection=enable_all,
        enable_content_filter=enable_all,
        custom_blocklist=custom_blocklist
    )
    return AutomatedSecurityCallback(analyzer)


  

"""
TLS Inspector - Stage 3
TLS/SSL inspection with dual-mode support.
"""
import re
import logging
from typing import Set

from .context import InspectionContext, TLSInspectionResult

logger = logging.getLogger(__name__)


# Known malicious JA3 fingerprints (from threat intel)
MALICIOUS_JA3: Set[str] = {
    # Cobalt Strike default
    '72a589da586844d7f0818ce684948eea',
    # Metasploit default
    '3b5074b1b5d032e5620f69f9f700ff0e',
    # Emotet
    '4d7a28d6f2263ed61de88ca66eb011e3',
    # TrickBot
    '6734f37431670b3ab4292b8f60f29984',
    # Dridex
    '51c64c77e60f3980eea90869b68c58a8',
    # Generic malware/RAT
    '9e10692f1b7f78228b2d4e424db3a98c',
    'a0e9f5d64349fb13191bc781f81f42e1',
    '5d65ea3fb1d4aa7d826733f2cd2b0bee',
}

# Suspicious SNI patterns (C2, malware infrastructure)
SUSPICIOUS_SNI_PATTERNS = [
    r'\.top$',
    r'\.xyz$',
    r'\.ru$',
    r'\.cn$',
    r'\.tk$',
    r'\.ml$',
    r'\.ga$',
    r'\.cf$',
    r'\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}',  # IP in domain
    r'[a-z0-9]{20,}\.com',  # DGA-like
    r'[a-z0-9]{15,}\.(net|org|info)',  # DGA-like
    r'localhost',
    r'^[\d.]+$',  # Pure IP
]

# Known phishing/malicious domain keywords
PHISHING_KEYWORDS = [
    'paypal-', 'paypa1', 'paypai',
    'amazon-', 'amaz0n', 'amazn',
    'apple-', 'app1e', 'appie',
    'microsoft-', 'micros0ft', 'mircosoft',
    'google-', 'g00gle', 'gogle',
    'facebook-', 'faceb00k', 'faceboak',
    'login-', 'signin-', 'verify-', 'secure-',
    'update-', 'confirm-', 'account-',
]


class TLSInspector:
    """
    Stage 3: TLS Inspection
    
    Supports two modes:
    - Mode A: Decrypted payload available - full DPI
    - Mode B: Metadata only - SNI/JA3/cert analysis
    
    Does NOT implement MITM or key handling.
    """
    
    def __init__(self):
        self._suspicious_sni_patterns = [
            re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_SNI_PATTERNS
        ]
    
    def inspect(self, ctx: InspectionContext) -> None:
        """
        Inspect TLS metadata and/or decrypted content.
        Updates ctx.tls_result with findings.
        """
        result = TLSInspectionResult()
        
        tls_meta = ctx.metadata.tls_metadata
        if not tls_meta:
            # No TLS metadata - skip TLS inspection
            result.mode = "none"
            ctx.tls_result = result
            return
        
        if tls_meta.is_decrypted:
            # Mode A: Full inspection on decrypted payload
            result.mode = "decrypted"
            # Decrypted content is analyzed by other stages
            # Here we just note the mode
        else:
            # Mode B: Metadata-only analysis
            result.mode = "metadata_only"
        
        # Analyze JA3 fingerprint
        if tls_meta.ja3:
            if self._check_malicious_ja3(tls_meta.ja3):
                result.suspicious_fingerprint = True
                result.risk_score += 0.8
                logger.warning(f"Malicious JA3 fingerprint detected: {tls_meta.ja3}")
        
        # Analyze SNI
        if tls_meta.sni:
            sni_risk = self._analyze_sni(tls_meta.sni)
            if sni_risk > 0:
                result.suspicious_domain = True
                result.risk_score += sni_risk
        
        # Analyze certificate if available
        if tls_meta.cert_cn:
            cert_issues = self._analyze_certificate(tls_meta)
            result.cert_issues = cert_issues
            if cert_issues:
                result.risk_score += 0.1 * len(cert_issues)
        
        # Cap risk score at 1.0
        result.risk_score = min(1.0, result.risk_score)
        
        ctx.tls_result = result
        
        if result.risk_score > 0.5:
            logger.info(
                f"TLS inspection found risks: "
                f"fingerprint={result.suspicious_fingerprint}, "
                f"domain={result.suspicious_domain}, "
                f"score={result.risk_score:.2f}"
            )
    
    def _check_malicious_ja3(self, ja3: str) -> bool:
        """Check if JA3 fingerprint is known malicious."""
        return ja3.lower() in MALICIOUS_JA3
    
    def _analyze_sni(self, sni: str) -> float:
        """
        Analyze SNI for suspicious patterns.
        Returns risk score 0.0-1.0.
        """
        sni_lower = sni.lower()
        risk = 0.0
        
        # Check against suspicious patterns
        for pattern in self._suspicious_sni_patterns:
            if pattern.search(sni_lower):
                risk += 0.3
                break
        
        # Check for phishing keywords
        for keyword in PHISHING_KEYWORDS:
            if keyword in sni_lower:
                risk += 0.5
                logger.warning(f"Phishing keyword in SNI: {keyword}")
                break
        
        # Check for excessive subdomains (often C2)
        subdomain_count = sni_lower.count('.')
        if subdomain_count > 4:
            risk += 0.2
        
        # Check domain length (DGA detection)
        domain_parts = sni_lower.split('.')
        if domain_parts:
            main_domain = domain_parts[0] if len(domain_parts) == 1 else domain_parts[-2]
            if len(main_domain) > 20:
                risk += 0.3  # Likely DGA
        
        return min(risk, 1.0)
    
    def _analyze_certificate(self, tls_meta) -> list:
        """
        Analyze certificate properties for issues.
        Returns list of issue descriptions.
        """
        issues = []
        
        cn = tls_meta.cert_cn
        sni = tls_meta.sni or ""
        
        if cn:
            # Check for mismatch between SNI and CN
            if sni and cn.lower() != sni.lower():
                # Allow wildcard certs
                if not cn.startswith('*.') or not sni.endswith(cn[1:]):
                    issues.append(f"CN/SNI mismatch: {cn} vs {sni}")
            
            # Check for self-signed indicators
            if 'localhost' in cn.lower() or cn.startswith('*.'):
                # Not necessarily an issue, but note it
                pass
            
            # Check for suspicious CN patterns
            for keyword in PHISHING_KEYWORDS:
                if keyword in cn.lower():
                    issues.append(f"Phishing keyword in certificate CN: {keyword}")
                    break
        
        return issues

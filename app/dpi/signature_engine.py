"""
Dynamic Signature Engine
Loads signatures from external sources with runtime updates.
"""
import re
import json
import time
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Pattern, Any
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
import httpx

from .context import InspectionContext, SignatureMatch, SignatureResult
from .constants import Severity
from .config import get_config
from .exceptions import SignatureCompilationError

logger = logging.getLogger(__name__)

# Thread pool for regex timeouts
_regex_executor: Optional[ThreadPoolExecutor] = None


def get_regex_executor() -> ThreadPoolExecutor:
    """Get or create regex execution thread pool."""
    global _regex_executor
    if _regex_executor is None:
        _regex_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="regex_")
    return _regex_executor


@dataclass
class SignatureRule:
    """Signature rule definition."""
    id: int
    name: str
    pattern: str
    severity: Severity
    category: str
    description: str = ""
    case_sensitive: bool = False
    enabled: bool = True
    tags: List[str] = field(default_factory=list)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SignatureRule":
        """Create SignatureRule from dictionary."""
        severity_map = {
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
            "critical": Severity.CRITICAL
        }
        return cls(
            id=data.get("id", 0),
            name=data.get("name", "Unknown"),
            pattern=data.get("pattern", ""),
            severity=severity_map.get(data.get("severity", "medium").lower(), Severity.MEDIUM),
            category=data.get("category", "unknown"),
            description=data.get("description", ""),
            case_sensitive=data.get("case_sensitive", False),
            enabled=data.get("enabled", True),
            tags=data.get("tags", [])
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "name": self.name,
            "pattern": self.pattern,
            "severity": self.severity.value,
            "category": self.category,
            "description": self.description,
            "case_sensitive": self.case_sensitive,
            "enabled": self.enabled,
            "tags": self.tags
        }


# Default built-in signatures (fallback if no external source)
DEFAULT_SIGNATURES: List[Dict[str, Any]] = [
    # SQL Injection
    {
        "id": 100001, "name": "SQL Injection - UNION SELECT",
        "pattern": r"(?:union\s+(?:all\s+)?select|select\s+[^;]+\s+from\s+[^;]+\s+where)",
        "severity": "high", "category": "sqli",
        "description": "Detects UNION-based SQL injection attempts"
    },
    {
        "id": 100002, "name": "SQL Injection - Boolean-based",
        "pattern": r"(?:'\s*(?:or|and)\s+['0-9]+=\s*['0-9]+|(?:or|and)\s+\d+\s*=\s*\d+)",
        "severity": "high", "category": "sqli"
    },
    {
        "id": 100003, "name": "SQL Injection - Time-based",
        "pattern": r"(?:sleep\s*\(|benchmark\s*\(|waitfor\s+delay|pg_sleep)",
        "severity": "high", "category": "sqli"
    },
    {
        "id": 100004, "name": "SQL Injection - Comment",
        "pattern": r"(?:'\s*--\s*|'\s*#\s*|/\*.*?\*/)",
        "severity": "medium", "category": "sqli"
    },
    {
        "id": 100005, "name": "SQL Injection - Stacked Queries",
        "pattern": r"(?:;\s*(?:drop|delete|update|insert|alter|create)\s+)",
        "severity": "critical", "category": "sqli"
    },
    
    # XSS
    {
        "id": 100010, "name": "XSS - Script Tag",
        "pattern": r"<\s*script[^>]*>|<\s*/\s*script\s*>",
        "severity": "high", "category": "xss"
    },
    {
        "id": 100011, "name": "XSS - Event Handler",
        "pattern": r"(?:on(?:error|load|click|mouse|focus|blur|key|submit|change)\s*=)",
        "severity": "high", "category": "xss"
    },
    {
        "id": 100012, "name": "XSS - JavaScript URI",
        "pattern": r"(?:javascript\s*:|data\s*:\s*text/html|vbscript\s*:)",
        "severity": "high", "category": "xss"
    },
    {
        "id": 100013, "name": "XSS - SVG/Embed",
        "pattern": r"<\s*(?:svg|embed|object|iframe|frame|applet)[^>]*>",
        "severity": "medium", "category": "xss"
    },
    
    # Command Injection
    {
        "id": 100020, "name": "Command Injection - Shell Metachar",
        "pattern": r"(?:[;&|`$]\s*(?:cat|ls|dir|whoami|id|pwd|uname|hostname|ifconfig|ipconfig|rm|mv|cp|chmod|chown))",
        "severity": "critical", "category": "cmdi"
    },
    {
        "id": 100021, "name": "Command Injection - Chaining",
        "pattern": r"(?:\|\s*(?:cat|head|tail|less|more|nc|curl|wget|bash|sh|cmd|rm|mv|cp))",
        "severity": "critical", "category": "cmdi"
    },
    {
        "id": 100022, "name": "Command Injection - Backtick",
        "pattern": r"`[^`]{1,100}`",
        "severity": "high", "category": "cmdi"
    },
    {
        "id": 100023, "name": "Command Injection - Common Paths",
        "pattern": r"(?:/bin/(?:bash|sh|dash|zsh)|/etc/(?:passwd|shadow)|/proc/self)",
        "severity": "critical", "category": "cmdi"
    },
    
    # Path Traversal
    {
        "id": 100030, "name": "Path Traversal - Basic",
        "pattern": r"(?:\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%2e%2e%5c)",
        "severity": "high", "category": "traversal"
    },
    {
        "id": 100031, "name": "Path Traversal - Encoded",
        "pattern": r"(?:%252e%252e%252f|%c0%ae%c0%ae%c0%af|%uff0e%uff0e%uff0f)",
        "severity": "high", "category": "traversal"
    },
    
    # LDAP Injection
    {
        "id": 100040, "name": "LDAP Injection - Filter",
        "pattern": r"(?:\)\s*\(\s*[&|!]|\*\s*\)\s*\()",
        "severity": "high", "category": "ldap"
    },
    
    # Template Injection
    {
        "id": 100050, "name": "SSTI - Jinja2",
        "pattern": r"(?:\{\{\s*[^}]{1,50}\s*\}\}|\{%\s*[^%]{1,50}\s*%\})",
        "severity": "high", "category": "ssti"
    },
    {
        "id": 100051, "name": "SSTI - Expression Language",
        "pattern": r"(?:\$\{[^}]{1,100}\}|<%[^%]{1,100}%>)",
        "severity": "high", "category": "ssti"
    },
    
    # Deserialization
    {
        "id": 100060, "name": "Java Deserialization",
        "pattern": r"(?:rO0AB|ysoserial|java\.lang\.Runtime)",
        "severity": "critical", "category": "deser"
    },
    {
        "id": 100061, "name": "PHP Object Injection",
        "pattern": r"(?:O:\d{1,3}:\"[^\"]{1,50}\":\d{1,3}:\{)",
        "severity": "critical", "category": "deser"
    },
    
    # Webshell/Malware
    {
        "id": 100070, "name": "Webshell - PHP",
        "pattern": r"(?:eval\s*\(\s*(?:base64_decode|gzinflate|\$_(?:POST|GET|REQUEST)))",
        "severity": "critical", "category": "malware"
    },
    {
        "id": 100071, "name": "Webshell - System Commands",
        "pattern": r"(?:system\s*\(|exec\s*\(|shell_exec\s*\(|passthru\s*\(|popen\s*\()",
        "severity": "critical", "category": "malware"
    },
    {
        "id": 100072, "name": "C2 Beacon",
        "pattern": r"(?:beacon|meterpreter|empire|cobalt|havoc|sliver)",
        "severity": "critical", "category": "c2"
    },
    
    # XXE
    {
        "id": 100080, "name": "XXE - DOCTYPE",
        "pattern": r"(?:<!DOCTYPE[^>]{1,200}\[|<!ENTITY[^>]{1,200}SYSTEM|<!ENTITY[^>]{1,200}PUBLIC)",
        "severity": "high", "category": "xxe"
    },
    
    # Log4Shell
    {
        "id": 100100, "name": "Log4Shell",
        "pattern": r"(?:\$\{jndi:(?:ldap|rmi|dns|iiop|corba|nds|http):)",
        "severity": "critical", "category": "exploit"
    },
]


class SignatureLoader:
    """Dynamic signature loader supporting multiple sources."""
    
    def __init__(self):
        self._config = get_config().signatures
        self._last_load_time = 0
        self._signatures: List[SignatureRule] = []
    
    def load_signatures(self) -> List[SignatureRule]:
        """Load signatures from configured sources."""
        signatures = []
        
        # Try loading from file first
        if self._config.signatures_file:
            try:
                file_sigs = self._load_from_file(self._config.signatures_file)
                signatures.extend(file_sigs)
                logger.info(f"Loaded {len(file_sigs)} signatures from file")
            except Exception as e:
                logger.error(f"Failed to load signatures from file: {e}")
        
        # Try loading from URL
        if self._config.signatures_url:
            try:
                url_sigs = self._load_from_url(self._config.signatures_url)
                signatures.extend(url_sigs)
                logger.info(f"Loaded {len(url_sigs)} signatures from URL")
            except Exception as e:
                logger.error(f"Failed to load signatures from URL: {e}")
        
        # Fall back to defaults if no external sources
        if not signatures:
            logger.info("Using default built-in signatures")
            signatures = [SignatureRule.from_dict(s) for s in DEFAULT_SIGNATURES]
        
        self._signatures = signatures
        self._last_load_time = time.time()
        return signatures
    
    def _load_from_file(self, filepath: str) -> List[SignatureRule]:
        """Load signatures from JSON or YAML file."""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Signatures file not found: {filepath}")
        
        content = path.read_text(encoding='utf-8')
        
        if filepath.endswith('.yaml') or filepath.endswith('.yml'):
            import yaml
            data = yaml.safe_load(content)
        else:
            data = json.loads(content)
        
        if isinstance(data, dict) and 'signatures' in data:
            data = data['signatures']
        
        return [SignatureRule.from_dict(s) for s in data if s.get('enabled', True)]
    
    def _load_from_url(self, url: str) -> List[SignatureRule]:
        """Load signatures from remote URL."""
        response = httpx.get(url, timeout=30.0)
        response.raise_for_status()
        
        data = response.json()
        
        if isinstance(data, dict) and 'signatures' in data:
            data = data['signatures']
        
        return [SignatureRule.from_dict(s) for s in data if s.get('enabled', True)]
    
    def should_refresh(self) -> bool:
        """Check if signatures should be refreshed."""
        if self._config.signatures_refresh_interval <= 0:
            return False
        return time.time() - self._last_load_time > self._config.signatures_refresh_interval
    
    def export_signatures(self, filepath: str) -> None:
        """Export current signatures to file."""
        data = {"signatures": [s.to_dict() for s in self._signatures]}
        Path(filepath).write_text(json.dumps(data, indent=2))


class SignatureEngine:
    """
    Dynamic Signature Matching Engine.
    
    Features:
    - Load signatures from file, URL, or defaults
    - Runtime signature updates
    - ReDoS-safe pattern validation
    - Per-regex execution timeout
    """
    
    REGEX_TIMEOUT_MS = 100
    
    def __init__(self):
        self._loader = SignatureLoader()
        self._compiled_rules: Dict[int, Pattern] = {}
        self._rules_by_id: Dict[int, SignatureRule] = {}
        self._rejected_patterns: List[int] = []
        self._initialized = False
    
    def initialize(self) -> None:
        """Load and compile signature patterns."""
        logger.info("Loading signature patterns...")
        
        signatures = self._loader.load_signatures()
        self._compile_signatures(signatures)
        self._initialized = True
    
    def _compile_signatures(self, signatures: List[SignatureRule]) -> None:
        """Compile all signature patterns safely."""
        self._compiled_rules.clear()
        self._rules_by_id.clear()
        self._rejected_patterns.clear()
        
        compiled_count = 0
        rejected_count = 0
        
        for rule in signatures:
            if not rule.enabled:
                continue
            
            if not self._is_safe_pattern(rule.pattern):
                logger.warning(f"Rejecting unsafe pattern: {rule.id} ({rule.name})")
                self._rejected_patterns.append(rule.id)
                rejected_count += 1
                continue
            
            try:
                flags = 0 if rule.case_sensitive else re.IGNORECASE
                compiled = re.compile(rule.pattern, flags)
                self._compiled_rules[rule.id] = compiled
                self._rules_by_id[rule.id] = rule
                compiled_count += 1
            except re.error as e:
                logger.error(f"Pattern compilation error: {rule.id} - {e}")
                self._rejected_patterns.append(rule.id)
                rejected_count += 1
        
        logger.info(f"Compiled {compiled_count} signatures, rejected {rejected_count}")
    
    def _is_safe_pattern(self, pattern: str) -> bool:
        """Check for ReDoS-prone patterns."""
        # Nested quantifiers
        if re.search(r'\([^)]*[*+]\)\s*[*+?]', pattern):
            return False
        if re.search(r'\([^)]*[*+]\)\s*\{', pattern):
            return False
        return True
    
    def refresh_if_needed(self) -> None:
        """Refresh signatures if refresh interval elapsed."""
        if self._loader.should_refresh():
            logger.info("Refreshing signatures...")
            signatures = self._loader.load_signatures()
            self._compile_signatures(signatures)
    
    def add_signature(self, rule: SignatureRule) -> bool:
        """Add a new signature at runtime."""
        if not self._is_safe_pattern(rule.pattern):
            logger.warning(f"Cannot add unsafe pattern: {rule.id}")
            return False
        
        try:
            flags = 0 if rule.case_sensitive else re.IGNORECASE
            compiled = re.compile(rule.pattern, flags)
            self._compiled_rules[rule.id] = compiled
            self._rules_by_id[rule.id] = rule
            logger.info(f"Added signature: {rule.id} ({rule.name})")
            return True
        except re.error as e:
            logger.error(f"Failed to add signature {rule.id}: {e}")
            return False
    
    def remove_signature(self, rule_id: int) -> bool:
        """Remove a signature at runtime."""
        if rule_id in self._compiled_rules:
            del self._compiled_rules[rule_id]
            del self._rules_by_id[rule_id]
            logger.info(f"Removed signature: {rule_id}")
            return True
        return False
    
    def get_signature_count(self) -> int:
        """Get count of active signatures."""
        return len(self._compiled_rules)
    
    def match(self, ctx: InspectionContext) -> None:
        """Match payload against all signatures."""
        if not self._initialized:
            self.initialize()
        
        # Check if refresh needed
        self.refresh_if_needed()
        
        matches: List[SignatureMatch] = []
        text = ctx.get_inspection_text()
        
        for rule_id, pattern in self._compiled_rules.items():
            rule = self._rules_by_id[rule_id]
            
            match_result = self._safe_regex_search(pattern, text, rule_id)
            
            if match_result:
                sig_match = SignatureMatch(
                    id=rule_id,
                    name=rule.name,
                    offset=match_result.start(),
                    severity=rule.severity,
                    confidence=0.9
                )
                matches.append(sig_match)
        
        # Calculate score
        score = 0.0
        if matches:
            severity_scores = {
                Severity.LOW: 0.25,
                Severity.MEDIUM: 0.5,
                Severity.HIGH: 0.75,
                Severity.CRITICAL: 1.0
            }
            max_severity = max(m.severity for m in matches)
            score = severity_scores.get(max_severity, 0.5)
            
            if len(matches) > 1:
                score = min(1.0, score + 0.05 * (len(matches) - 1))
        
        ctx.signature_result = SignatureResult(
            matches=matches,
            score=score
        )
        
        if matches:
            logger.info(f"Signature matches: {len(matches)}")
    
    def _safe_regex_search(
        self,
        pattern: Pattern,
        text: str,
        rule_id: int
    ) -> Optional[re.Match]:
        """Execute regex with hard timeout."""
        executor = get_regex_executor()
        timeout_sec = self.REGEX_TIMEOUT_MS / 1000.0
        
        def do_search():
            return pattern.search(text)
        
        try:
            future = executor.submit(do_search)
            return future.result(timeout=timeout_sec)
        except FuturesTimeoutError:
            logger.warning(f"Regex timeout: rule {rule_id}")
            return None
        except Exception as e:
            logger.debug(f"Regex error: rule {rule_id} - {e}")
            return None




    

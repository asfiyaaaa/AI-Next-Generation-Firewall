"""
Dynamic Application Identifier
Loads app signatures from external sources with runtime updates.
"""
import re
import json
import time
import logging
from pathlib import Path
from typing import Optional, Tuple, Dict, List, Any
from dataclasses import dataclass, field
import httpx

from .context import InspectionContext, ApplicationResult
from .config import get_config

logger = logging.getLogger(__name__)


@dataclass
class AppSignature:
    """Application signature definition."""
    id: str
    name: str
    category: str
    patterns: List[str] = field(default_factory=list)
    tls_sni_patterns: List[str] = field(default_factory=list)
    risk_level: float = 0.0
    confidence_boost: float = 0.0
    enabled: bool = True
    
    @classmethod
    def from_dict(cls, app_id: str, data: Dict[str, Any]) -> "AppSignature":
        """Create AppSignature from dictionary."""
        return cls(
            id=app_id,
            name=data.get("name", app_id),
            category=data.get("category", "unknown"),
            patterns=data.get("patterns", []),
            tls_sni_patterns=data.get("tls_sni_patterns", []),
            risk_level=data.get("risk_level", 0.0),
            confidence_boost=data.get("confidence_boost", 0.0),
            enabled=data.get("enabled", True)
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "category": self.category,
            "patterns": self.patterns,
            "tls_sni_patterns": self.tls_sni_patterns,
            "risk_level": self.risk_level,
            "confidence_boost": self.confidence_boost,
            "enabled": self.enabled
        }


# Default built-in signatures (fallback)
DEFAULT_APP_SIGNATURES: Dict[str, Dict[str, Any]] = {
    # Web Browsers
    "chrome": {
        "name": "Google Chrome", "category": "web-browser",
        "patterns": [r"Chrome/[\d.]+", r"Chromium/[\d.]+"],
        "tls_sni_patterns": ["google.com", "googleapis.com", "gstatic.com"],
        "risk_level": 0.0
    },
    "firefox": {
        "name": "Mozilla Firefox", "category": "web-browser",
        "patterns": [r"Firefox/[\d.]+", r"Gecko/\d+"],
        "tls_sni_patterns": ["mozilla.org", "firefox.com"],
        "risk_level": 0.0
    },
    "edge": {
        "name": "Microsoft Edge", "category": "web-browser",
        "patterns": [r"Edg/[\d.]+", r"Edge/[\d.]+"],
        "tls_sni_patterns": ["microsoft.com", "msedge.net"],
        "risk_level": 0.0
    },
    "safari": {
        "name": "Apple Safari", "category": "web-browser",
        "patterns": [r"Safari/[\d.]+", r"AppleWebKit/[\d.]+"],
        "tls_sni_patterns": ["apple.com", "icloud.com"],
        "risk_level": 0.0
    },
    
    # Messaging
    "whatsapp": {
        "name": "WhatsApp", "category": "messaging",
        "patterns": [r"WhatsApp/[\d.]+", r"WA-[\d.]+"],
        "tls_sni_patterns": ["whatsapp.com", "whatsapp.net", "wa.me"],
        "risk_level": 0.1
    },
    "telegram": {
        "name": "Telegram", "category": "messaging",
        "patterns": [r"Telegram", r"TelegramBot"],
        "tls_sni_patterns": ["telegram.org", "t.me", "telegram.me"],
        "risk_level": 0.1
    },
    "slack": {
        "name": "Slack", "category": "messaging",
        "patterns": [r"Slack", r"Slackbot"],
        "tls_sni_patterns": ["slack.com", "slack-edge.com"],
        "risk_level": 0.0
    },
    "discord": {
        "name": "Discord", "category": "messaging",
        "patterns": [r"Discord", r"DiscordBot"],
        "tls_sni_patterns": ["discord.com", "discord.gg", "discordapp.com"],
        "risk_level": 0.2
    },
    "teams": {
        "name": "Microsoft Teams", "category": "messaging",
        "patterns": [r"Teams", r"SkypeSpaces"],
        "tls_sni_patterns": ["teams.microsoft.com", "teams.live.com"],
        "risk_level": 0.0
    },
    "zoom": {
        "name": "Zoom", "category": "video-conferencing",
        "patterns": [r"Zoom", r"ZoomWebClient"],
        "tls_sni_patterns": ["zoom.us", "zoomgov.com"],
        "risk_level": 0.0
    },
    
    # Social Media
    "facebook": {
        "name": "Facebook", "category": "social-media",
        "patterns": [r"FBAN/", r"FB_IAB", r"facebook"],
        "tls_sni_patterns": ["facebook.com", "fb.com", "fbcdn.net"],
        "risk_level": 0.1
    },
    "instagram": {
        "name": "Instagram", "category": "social-media",
        "patterns": [r"Instagram", r"instagrambot"],
        "tls_sni_patterns": ["instagram.com", "cdninstagram.com"],
        "risk_level": 0.1
    },
    "twitter": {
        "name": "Twitter/X", "category": "social-media",
        "patterns": [r"Twitter", r"Twitterbot"],
        "tls_sni_patterns": ["twitter.com", "x.com", "twimg.com"],
        "risk_level": 0.1
    },
    "tiktok": {
        "name": "TikTok", "category": "social-media",
        "patterns": [r"TikTok", r"BytedanceWebview"],
        "tls_sni_patterns": ["tiktok.com", "tiktokcdn.com", "bytedance.com"],
        "risk_level": 0.2
    },
    "linkedin": {
        "name": "LinkedIn", "category": "social-media",
        "patterns": [r"LinkedIn"],
        "tls_sni_patterns": ["linkedin.com", "licdn.com"],
        "risk_level": 0.0
    },
    
    # Streaming
    "youtube": {
        "name": "YouTube", "category": "streaming",
        "patterns": [r"YouTube", r"Youtubei", r"com.google.android.youtube"],
        "tls_sni_patterns": ["youtube.com", "youtu.be", "ytimg.com", "googlevideo.com"],
        "risk_level": 0.0
    },
    "netflix": {
        "name": "Netflix", "category": "streaming",
        "patterns": [r"Netflix", r"NFLX"],
        "tls_sni_patterns": ["netflix.com", "nflxvideo.net"],
        "risk_level": 0.0
    },
    "spotify": {
        "name": "Spotify", "category": "streaming",
        "patterns": [r"Spotify/[\d.]+", r"spotify-"],
        "tls_sni_patterns": ["spotify.com", "scdn.co", "spotifycdn.com"],
        "risk_level": 0.0
    },
    "twitch": {
        "name": "Twitch", "category": "streaming",
        "patterns": [r"Twitch"],
        "tls_sni_patterns": ["twitch.tv", "ttvnw.net", "jtvnw.net"],
        "risk_level": 0.1
    },
    
    # Cloud Services
    "aws": {
        "name": "Amazon Web Services", "category": "cloud",
        "patterns": [r"aws-sdk", r"Amazon", r"EC2"],
        "tls_sni_patterns": ["amazonaws.com", "aws.amazon.com"],
        "risk_level": 0.0
    },
    "azure": {
        "name": "Microsoft Azure", "category": "cloud",
        "patterns": [r"Azure", r"WindowsAzure"],
        "tls_sni_patterns": ["azure.com", "azurewebsites.net", "azure-api.net"],
        "risk_level": 0.0
    },
    "gcp": {
        "name": "Google Cloud Platform", "category": "cloud",
        "patterns": [r"gcloud", r"google-cloud"],
        "tls_sni_patterns": ["googleapis.com", "cloud.google.com", "appspot.com"],
        "risk_level": 0.0
    },
    "dropbox": {
        "name": "Dropbox", "category": "cloud-storage",
        "patterns": [r"Dropbox", r"dropbox-android"],
        "tls_sni_patterns": ["dropbox.com", "dropboxapi.com"],
        "risk_level": 0.1
    },
    "onedrive": {
        "name": "Microsoft OneDrive", "category": "cloud-storage",
        "patterns": [r"OneDrive", r"LiveSDK"],
        "tls_sni_patterns": ["onedrive.live.com", "onedrive.com"],
        "risk_level": 0.0
    },
    
    # Development
    "git": {
        "name": "Git", "category": "development",
        "patterns": [r"git/[\d.]+", r"git-lfs"],
        "tls_sni_patterns": ["github.com", "gitlab.com", "bitbucket.org"],
        "risk_level": 0.0
    },
    "npm": {
        "name": "npm", "category": "development",
        "patterns": [r"npm/[\d.]+", r"node/[\d.]+"],
        "tls_sni_patterns": ["npmjs.org", "npmjs.com"],
        "risk_level": 0.1
    },
    "docker": {
        "name": "Docker", "category": "development",
        "patterns": [r"docker/[\d.]+", r"Docker-Client"],
        "tls_sni_patterns": ["docker.io", "docker.com"],
        "risk_level": 0.1
    },
    "pip": {
        "name": "Python pip", "category": "development",
        "patterns": [r"pip/[\d.]+", r"python-requests"],
        "tls_sni_patterns": ["pypi.org", "pythonhosted.org"],
        "risk_level": 0.1
    },
    
    # VPN/Anonymizers (High Risk)
    "openvpn": {
        "name": "OpenVPN", "category": "vpn",
        "patterns": [r"OpenVPN"],
        "risk_level": 0.5
    },
    "wireguard": {
        "name": "WireGuard", "category": "vpn",
        "patterns": [r"WireGuard"],
        "risk_level": 0.5
    },
    "tor": {
        "name": "Tor", "category": "anonymizer",
        "patterns": [r"Tor", r"AUTHENTICATE"],
        "tls_sni_patterns": ["torproject.org"],
        "risk_level": 0.8
    },
    
    # C2/Malware (Critical Risk)
    "cobalt_strike": {
        "name": "Cobalt Strike", "category": "c2",
        "patterns": [r"beacon"],
        "risk_level": 1.0
    },
    "metasploit": {
        "name": "Metasploit", "category": "exploit-framework",
        "patterns": [r"metasploit", r"meterpreter"],
        "risk_level": 1.0
    },
    
    # Protocols
    "grpc": {
        "name": "gRPC", "category": "rpc",
        "patterns": [r"grpc", r"application/grpc"],
        "risk_level": 0.1
    },
    "graphql": {
        "name": "GraphQL", "category": "api",
        "patterns": [r'query\s*\{', r'mutation\s*\{', r'"query":\s*"'],
        "risk_level": 0.1
    },
    
    # Email
    "smtp": {
        "name": "SMTP", "category": "email",
        "patterns": [r"EHLO ", r"MAIL FROM:", r"RCPT TO:"],
        "risk_level": 0.2
    },
    "imap": {
        "name": "IMAP", "category": "email",
        "patterns": [r"\* OK ", r"LOGIN ", r"SELECT "],
        "risk_level": 0.2
    },
}


class AppSignatureLoader:
    """Dynamic app signature loader."""
    
    def __init__(self):
        self._config = get_config().app_id
        self._last_load_time = 0
        self._signatures: Dict[str, AppSignature] = {}
    
    def load_signatures(self) -> Dict[str, AppSignature]:
        """Load signatures from configured sources."""
        signatures = {}
        
        # Try loading from file
        if self._config.app_signatures_file:
            try:
                file_sigs = self._load_from_file(self._config.app_signatures_file)
                signatures.update(file_sigs)
                logger.info(f"Loaded {len(file_sigs)} app signatures from file")
            except Exception as e:
                logger.error(f"Failed to load app signatures from file: {e}")
        
        # Try loading from URL
        if self._config.app_signatures_url:
            try:
                url_sigs = self._load_from_url(self._config.app_signatures_url)
                signatures.update(url_sigs)
                logger.info(f"Loaded {len(url_sigs)} app signatures from URL")
            except Exception as e:
                logger.error(f"Failed to load app signatures from URL: {e}")
        
        # Fall back to defaults
        if not signatures:
            logger.info("Using default built-in app signatures")
            for app_id, data in DEFAULT_APP_SIGNATURES.items():
                signatures[app_id] = AppSignature.from_dict(app_id, data)
        
        self._signatures = signatures
        self._last_load_time = time.time()
        return signatures
    
    def _load_from_file(self, filepath: str) -> Dict[str, AppSignature]:
        """Load from JSON/YAML file."""
        path = Path(filepath)
        content = path.read_text(encoding='utf-8')
        
        if filepath.endswith(('.yaml', '.yml')):
            import yaml
            data = yaml.safe_load(content)
        else:
            data = json.loads(content)
        
        if isinstance(data, dict) and 'applications' in data:
            data = data['applications']
        
        return {
            app_id: AppSignature.from_dict(app_id, app_data)
            for app_id, app_data in data.items()
            if app_data.get('enabled', True)
        }
    
    def _load_from_url(self, url: str) -> Dict[str, AppSignature]:
        """Load from remote URL."""
        response = httpx.get(url, timeout=30.0)
        response.raise_for_status()
        data = response.json()
        
        if isinstance(data, dict) and 'applications' in data:
            data = data['applications']
        
        return {
            app_id: AppSignature.from_dict(app_id, app_data)
            for app_id, app_data in data.items()
        }
    
    def should_refresh(self) -> bool:
        """Check if refresh is needed."""
        if self._config.app_signatures_refresh_interval <= 0:
            return False
        return time.time() - self._last_load_time > self._config.app_signatures_refresh_interval


class ApplicationIdentifier:
    """
    Dynamic Application Identifier.
    
    Features:
    - Load signatures from file, URL, or defaults
    - Payload-based identification
    - TLS SNI matching
    - Runtime signature updates
    """
    
    def __init__(self):
        self._loader = AppSignatureLoader()
        self._signatures: Dict[str, AppSignature] = {}
        self._compiled_patterns: Dict[str, List[re.Pattern]] = {}
        self._initialized = False
    
    def initialize(self) -> None:
        """Load and compile patterns."""
        self._signatures = self._loader.load_signatures()
        self._compile_patterns()
        self._initialized = True
        logger.info(f"Loaded {len(self._signatures)} application signatures")
    
    def _compile_patterns(self) -> None:
        """Compile all regex patterns."""
        self._compiled_patterns.clear()
        for app_id, sig in self._signatures.items():
            if sig.patterns:
                self._compiled_patterns[app_id] = [
                    re.compile(p, re.IGNORECASE) for p in sig.patterns
                ]
    
    def refresh_if_needed(self) -> None:
        """Refresh if interval elapsed."""
        if self._loader.should_refresh():
            logger.info("Refreshing app signatures...")
            self._signatures = self._loader.load_signatures()
            self._compile_patterns()
    
    def get_signature_count(self) -> int:
        """Get count of loaded signatures."""
        return len(self._signatures)
    
    def identify(self, ctx: InspectionContext) -> None:
        """Identify the application from context."""
        if not self._initialized:
            self.initialize()
        
        self.refresh_if_needed()
        
        candidates: List[Tuple[str, float]] = []
        text = ctx.get_inspection_text()
        
        # Check payload patterns
        for app_id, patterns in self._compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(text):
                    sig = self._signatures[app_id]
                    confidence = 0.7 + sig.confidence_boost
                    candidates.append((app_id, confidence))
                    break
        
        # Check TLS SNI patterns
        if ctx.metadata.tls_metadata and ctx.metadata.tls_metadata.sni:
            sni = ctx.metadata.tls_metadata.sni.lower()
            for app_id, sig in self._signatures.items():
                if sig.tls_sni_patterns:
                    for sni_pattern in sig.tls_sni_patterns:
                        if sni_pattern in sni or sni.endswith('.' + sni_pattern):
                            existing = next((c for c in candidates if c[0] == app_id), None)
                            if existing:
                                idx = candidates.index(existing)
                                candidates[idx] = (app_id, min(0.98, existing[1] + 0.2))
                            else:
                                candidates.append((app_id, 0.85))
                            break
        
        # Check HTTP patterns
        if b'HTTP/' in ctx.raw_payload or 'HTTP/' in text:
            http_app = self._identify_http_app(text, ctx)
            if http_app:
                candidates.append(http_app)
        
        # Select best candidate
        if candidates:
            candidates.sort(key=lambda x: x[1], reverse=True)
            best_app_id, confidence = candidates[0]
            sig = self._signatures[best_app_id]
            
            ctx.app_result = ApplicationResult(
                application=sig.name,
                confidence=min(confidence, 0.99),
                category=sig.category,
                risk_level=sig.risk_level
            )
        else:
            ctx.app_result = ApplicationResult(
                application="Unknown",
                confidence=0.0,
                category="unknown",
                risk_level=0.2
            )
        
        logger.debug(f"App identified: {ctx.app_result.application}")
    
    def _identify_http_app(self, text: str, ctx: InspectionContext) -> Optional[Tuple[str, float]]:
        """Identify HTTP-based applications."""
        # Extract User-Agent
        ua_match = re.search(r'User-Agent:\s*([^\r\n]+)', text, re.IGNORECASE)
        if ua_match:
            ua = ua_match.group(1)
            for app_id, patterns in self._compiled_patterns.items():
                for pattern in patterns:
                    if pattern.search(ua):
                        return (app_id, 0.8)
        
        # Check Host header
        host_match = re.search(r'Host:\s*([^\r\n:]+)', text, re.IGNORECASE)
        if host_match:
            host = host_match.group(1).lower()
            for app_id, sig in self._signatures.items():
                if sig.tls_sni_patterns:
                    for sni_pattern in sig.tls_sni_patterns:
                        if sni_pattern in host:
                            return (app_id, 0.75)
        
        return None

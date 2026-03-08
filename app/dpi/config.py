"""
DPI Configuration Module
Centralized configuration with environment variable support.
"""
import os
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from functools import lru_cache
import logging

logger = logging.getLogger(__name__)


@dataclass
class ThreatIntelConfig:
    """Threat Intelligence API configuration."""
    # AbuseIPDB
    abuseipdb_api_key: str = ""
    abuseipdb_enabled: bool = True
    abuseipdb_confidence_weight: float = 0.9
    
    # VirusTotal
    virustotal_api_key: str = ""
    virustotal_enabled: bool = True
    virustotal_confidence_weight: float = 0.95
    
    # AlienVault OTX
    alienvault_api_key: str = ""
    alienvault_enabled: bool = True
    alienvault_confidence_weight: float = 0.85
    
    # MaxMind GeoIP
    maxmind_license_key: str = ""
    maxmind_account_id: str = ""
    maxmind_enabled: bool = True
    
    # Cache settings
    cache_ttl_seconds: int = 3600
    cache_max_size: int = 10000
    
    # Rate limiting
    rate_limit_per_minute: int = 100


@dataclass
class SignatureConfig:
    """Signature engine configuration."""
    # External signature sources
    signatures_file: str = ""  # Path to external signatures JSON/YAML
    signatures_url: str = ""   # URL to fetch signatures
    signatures_refresh_interval: int = 3600  # seconds
    
    # ReDoS protection
    regex_timeout_ms: int = 100
    max_pattern_complexity: int = 50


@dataclass
class AppIDConfig:
    """Application identification configuration."""
    # External app signatures
    app_signatures_file: str = ""
    app_signatures_url: str = ""
    app_signatures_refresh_interval: int = 3600


@dataclass 
class SafetyConfig:
    """Safety and resource limits."""
    max_payload_size: int = 10 * 1024 * 1024  # 10 MB
    max_decode_depth: int = 3
    max_stage_timeout_ms: int = 2000
    max_total_timeout_ms: int = 15000
    max_regex_timeout_ms: int = 100


@dataclass
class DPIConfig:
    """Master DPI configuration."""
    # Sub-configurations
    threat_intel: ThreatIntelConfig = field(default_factory=ThreatIntelConfig)
    signatures: SignatureConfig = field(default_factory=SignatureConfig)
    app_id: AppIDConfig = field(default_factory=AppIDConfig)
    safety: SafetyConfig = field(default_factory=SafetyConfig)
    
    # General settings
    debug_mode: bool = False
    log_level: str = "INFO"
    
    @classmethod
    def from_env(cls) -> "DPIConfig":
        """Load configuration from environment variables."""
        config = cls()
        
        # Threat Intel API Keys
        config.threat_intel.abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY", "")
        config.threat_intel.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        config.threat_intel.alienvault_api_key = os.getenv("ALIENVAULT_API_KEY", "")
        config.threat_intel.maxmind_license_key = os.getenv("MAXMIND_LICENSE_KEY", "")
        config.threat_intel.maxmind_account_id = os.getenv("MAXMIND_ACCOUNT_ID", "")
        
        # Enable/disable based on key presence
        config.threat_intel.abuseipdb_enabled = bool(config.threat_intel.abuseipdb_api_key)
        config.threat_intel.virustotal_enabled = bool(config.threat_intel.virustotal_api_key)
        config.threat_intel.alienvault_enabled = bool(config.threat_intel.alienvault_api_key)
        config.threat_intel.maxmind_enabled = bool(config.threat_intel.maxmind_license_key)
        
        # External signature sources
        config.signatures.signatures_file = os.getenv("SIGNATURES_FILE", "")
        config.signatures.signatures_url = os.getenv("SIGNATURES_URL", "")
        
        # App-ID sources
        config.app_id.app_signatures_file = os.getenv("APP_SIGNATURES_FILE", "")
        config.app_id.app_signatures_url = os.getenv("APP_SIGNATURES_URL", "")
        
        # Safety settings
        if os.getenv("MAX_PAYLOAD_SIZE"):
            config.safety.max_payload_size = int(os.getenv("MAX_PAYLOAD_SIZE"))
        
        # Debug mode
        config.debug_mode = os.getenv("DEBUG", "").lower() in ("true", "1", "yes")
        config.log_level = os.getenv("LOG_LEVEL", "INFO")
        
        return config
    
    def validate(self) -> list:
        """Validate configuration and return list of warnings."""
        warnings = []
        
        if not self.threat_intel.abuseipdb_api_key:
            warnings.append("AbuseIPDB API key not configured - IP reputation disabled")
        if not self.threat_intel.virustotal_api_key:
            warnings.append("VirusTotal API key not configured - file hash lookup disabled")
        if not self.threat_intel.alienvault_api_key:
            warnings.append("AlienVault API key not configured - OTX feed disabled")
        if not self.threat_intel.maxmind_license_key:
            warnings.append("MaxMind license key not configured - GeoIP disabled")
        
        return warnings


# Global configuration instance
_config: Optional[DPIConfig] = None


def get_config() -> DPIConfig:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = DPIConfig.from_env()
        warnings = _config.validate()
        for w in warnings:
            # logger.warning(w)
            pass
    return _config


def set_config(config: DPIConfig) -> None:
    """Set the global configuration instance."""
    global _config
    _config = config


def reload_config() -> DPIConfig:
    """Reload configuration from environment."""
    global _config
    _config = DPIConfig.from_env()
    return _config

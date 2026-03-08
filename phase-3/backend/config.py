"""
Centralized Configuration Management for Security Features

Handles environment variables, feature toggles, API keys, and security policies.
"""

import os
from typing import Optional, List, Dict, Any
from pydantic import BaseSettings, Field
from pathlib import Path


class SecurityConfig(BaseSettings):
    """Security-related configuration settings."""
    
    # Application Settings
    APP_NAME: str = "RansomGuard Security Platform"
    DEBUG: bool = Field(default=False, env="DEBUG")
    SECRET_KEY: str = Field(default="your-secret-key-change-in-production", env="SECRET_KEY")
    
    # Google Safe Browsing API
    GOOGLE_SAFE_BROWSING_API_KEY: str = Field(default="", env="GOOGLE_SAFE_BROWSING_API_KEY")
    
    # LDAP/AD Configuration
    LDAP_SERVER: str = Field(default="ldap://localhost:389", env="LDAP_SERVER")
    LDAP_BASE_DN: str = Field(default="dc=example,dc=com", env="LDAP_BASE_DN")
    LDAP_ADMIN_DN: str = Field(default="cn=admin,dc=example,dc=com", env="LDAP_ADMIN_DN")
    LDAP_ADMIN_PASSWORD: str = Field(default="", env="LDAP_ADMIN_PASSWORD")
    LDAP_ENABLED: bool = Field(default=False, env="LDAP_ENABLED")
    
    # VPN Configuration
    VPN_SERVER_ADDRESS: str = Field(default="vpn.example.com", env="VPN_SERVER_ADDRESS")
    VPN_SERVER_PORT: int = Field(default=443, env="VPN_SERVER_PORT")
    VPN_ENABLED: bool = Field(default=False, env="VPN_ENABLED")
    
    # Anti-Bot Settings
    RATE_LIMIT_REQUESTS: int = Field(default=100, env="RATE_LIMIT_REQUESTS")
    RATE_LIMIT_WINDOW_SECONDS: int = Field(default=60, env="RATE_LIMIT_WINDOW_SECONDS")
    CAPTCHA_ENABLED: bool = Field(default=True, env="CAPTCHA_ENABLED")
    CAPTCHA_SITE_KEY: str = Field(default="", env="CAPTCHA_SITE_KEY")
    CAPTCHA_SECRET_KEY: str = Field(default="", env="CAPTCHA_SECRET_KEY")
    
    # Sandboxing Settings
    SANDBOX_TIMEOUT_SECONDS: int = Field(default=30, env="SANDBOX_TIMEOUT_SECONDS")
    SANDBOX_MAX_FILE_SIZE_MB: int = Field(default=50, env="SANDBOX_MAX_FILE_SIZE_MB")
    SANDBOX_ENABLED: bool = Field(default=True, env="SANDBOX_ENABLED")
    
    # VirusTotal API (for cloud-based sandbox analysis)
    # Get your free API key from: https://www.virustotal.com/gui/join-us
    # Free tier: 4 requests/minute, 500 requests/day
    VIRUSTOTAL_API_KEY: str = Field(default="308f33af9dad6302cbaa604cdf56a651429935e61997c50af6ff82957be41081", env="VIRUSTOTAL_API_KEY")
    USE_CLOUD_SANDBOX: bool = Field(default=True, env="USE_CLOUD_SANDBOX")
    CLOUD_SANDBOX_FALLBACK_TO_STATIC: bool = Field(default=True, env="CLOUD_SANDBOX_FALLBACK")
    
    # Content Filtering
    BLOCKED_FILE_EXTENSIONS: List[str] = Field(
        default=[".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".scr"],
        env="BLOCKED_FILE_EXTENSIONS"
    )
    MAX_UPLOAD_SIZE_MB: int = Field(default=100, env="MAX_UPLOAD_SIZE_MB")
    
    # URL Filtering
    URL_CATEGORIES: List[str] = Field(
        default=[
            "malware", "phishing", "adult", "gambling", "social_media",
            "streaming", "gaming", "shopping", "news", "business", "safe"
        ],
        env="URL_CATEGORIES"
    )
    
    # JWT Settings
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_HOURS: int = Field(default=24, env="JWT_EXPIRATION_HOURS")
    
    # Database paths (using SQLite for simplicity)
    DATA_DIR: Path = Path(__file__).parent.parent / "data"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


class URLCategory:
    """URL category definitions."""
    MALWARE = "malware"
    PHISHING = "phishing"
    ADULT = "adult"
    GAMBLING = "gambling"
    SOCIAL_MEDIA = "social_media"
    STREAMING = "streaming"
    GAMING = "gaming"
    SHOPPING = "shopping"
    NEWS = "news"
    BUSINESS = "business"
    SAFE = "safe"
    UNKNOWN = "unknown"


class ThreatLevel:
    """Threat level definitions."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"


# Default blocked domains for URL filtering
DEFAULT_BLOCKED_DOMAINS = [
    "malware-test.example.com",
    "phishing-test.example.com",
]

# Known malicious patterns
MALWARE_PATTERNS = [
    r"\.exe\.txt$",
    r"\.scr$",
    r"download.*trojan",
    r"free.*crack",
]

# Suspicious behavioral indicators for sandboxing
SUSPICIOUS_BEHAVIORS = [
    "mass_file_encryption",
    "registry_persistence",
    "network_c2_communication",
    "process_injection",
    "credential_access",
    "defense_evasion",
    "data_exfiltration",
]


def get_config() -> SecurityConfig:
    """Get the security configuration instance."""
    return SecurityConfig()


# Singleton config instance
config = get_config()

"""
URL Filtering and Categorization Module

Provides URL categorization, reputation checking, and blocking capabilities.
Integrates with Google Safe Browsing API and local blocklists.
"""

import re
import json
import hashlib
import logging
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import requests

logger = logging.getLogger(__name__)


@dataclass
class URLAnalysisResult:
    """Result of URL analysis."""
    url: str
    domain: str
    is_blocked: bool
    category: str
    threat_level: str  # critical, high, medium, low, safe
    reputation_score: int  # 0-100 (100 = safe)
    reasons: List[str]
    safe_browsing_result: Optional[Dict[str, Any]]
    analysis_timestamp: str


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
    EDUCATION = "education"
    GOVERNMENT = "government"
    SAFE = "safe"
    UNKNOWN = "unknown"


class URLFilter:
    """
    URL filtering and categorization engine.
    
    Provides:
    - Domain categorization
    - Blocklist/allowlist management
    - Google Safe Browsing integration
    - Reputation scoring
    """
    
    # Domain patterns for categorization
    CATEGORY_PATTERNS = {
        URLCategory.SOCIAL_MEDIA: [
            r"facebook\.com", r"twitter\.com", r"instagram\.com",
            r"linkedin\.com", r"tiktok\.com", r"snapchat\.com",
            r"reddit\.com", r"pinterest\.com", r"tumblr\.com"
        ],
        URLCategory.STREAMING: [
            r"youtube\.com", r"netflix\.com", r"hulu\.com",
            r"twitch\.tv", r"spotify\.com", r"soundcloud\.com",
            r"disneyplus\.com", r"primevideo\.com", r"hbomax\.com"
        ],
        URLCategory.GAMING: [
            r"steam\.com", r"epicgames\.com", r"origin\.com",
            r"roblox\.com", r"minecraft\.net", r"ea\.com",
            r"ubisoft\.com", r"blizzard\.com", r"playstation\.com"
        ],
        URLCategory.SHOPPING: [
            r"amazon\.com", r"ebay\.com", r"walmart\.com",
            r"aliexpress\.com", r"shopify\.com", r"etsy\.com",
            r"target\.com", r"bestbuy\.com"
        ],
        URLCategory.NEWS: [
            r"cnn\.com", r"bbc\.com", r"reuters\.com",
            r"nytimes\.com", r"washingtonpost\.com", r"theguardian\.com",
            r"foxnews\.com", r"nbcnews\.com", r"abcnews\.com"
        ],
        URLCategory.EDUCATION: [
            r"\.edu$", r"coursera\.org", r"udemy\.com",
            r"edx\.org", r"khanacademy\.org", r"wikipedia\.org"
        ],
        URLCategory.GOVERNMENT: [
            r"\.gov$", r"\.gov\.in$", r"\.mil$"
        ]
    }
    
    # Suspicious URL patterns
    SUSPICIOUS_PATTERNS = [
        r"login.*\.(?!com|org|net|edu|gov)",  # Fake login pages
        r"paypal.*(?<!paypal\.com)",
        r"bank.*(?<!\.bank\.com)",
        r"\.tk$", r"\.ml$", r"\.ga$", r"\.cf$",  # Free domains often used for phishing
        r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",  # IP addresses
        r"bit\.ly", r"tinyurl\.com",  # URL shorteners
        r"verify.*account",
        r"secure.*login",
        r"update.*payment",
    ]
    
    # Known malicious domains - managed via API
    MALICIOUS_DOMAINS = {}
    
    def __init__(self, google_api_key: str = ""):
        """
        Initialize URL filter.
        
        Args:
            google_api_key: Google Safe Browsing API key
        """
        self.google_api_key = google_api_key
        self.blocklist: Dict[str, str] = {}  # domain -> reason
        self.allowlist: List[str] = []
        self.cache: Dict[str, Tuple[URLAnalysisResult, datetime]] = {}
        self.cache_ttl = timedelta(hours=1)
        
        # Load existing blocklist and allowlist from database
        try:
            from . import database as db
            self.blocklist = db.get_blocklist()
            self.allowlist = db.get_allowlist()
            logger.info(f"Loaded {len(self.blocklist)} blocked domains and {len(self.allowlist)} allowed domains")
        except Exception as e:
            logger.warning(f"Could not load blocklist/allowlist from database: {e}")
    
    def analyze_url(self, url: str) -> URLAnalysisResult:
        """
        Analyze a URL for threats and categorization.
        
        Args:
            url: URL to analyze
            
        Returns:
            URLAnalysisResult with analysis details
        """
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Check cache (DISABLED FOR DEBUGGING/CONSISTENCY)
        # cache_key = hashlib.md5(url.encode()).hexdigest()
        # if cache_key in self.cache:
        #     cached_result, cached_time = self.cache[cache_key]
        #     if datetime.now() - cached_time < self.cache_ttl:
        #         return cached_result
        pass
        
        # Parse URL
        parsed = urlparse(url)
        domain = parsed.netloc.lower().strip()
        
        # Remove trailing dot if present
        if domain.endswith('.'):
            domain = domain[:-1]
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
            
        reasons = []
        is_blocked = False
        threat_level = "safe"
        reputation_score = 100
        category = URLCategory.UNKNOWN
        safe_browsing_result = None
        
        # Check allowlist first
        if self._is_allowlisted(domain):
            category = self._categorize_domain(domain)
            return URLAnalysisResult(
                url=url,
                domain=domain,
                is_blocked=False,
                category=category,
                threat_level="safe",
                reputation_score=100,
                reasons=["Domain is allowlisted"],
                safe_browsing_result=None,
                analysis_timestamp=datetime.utcnow().isoformat()
            )
        
        # Check in-memory blocklist
        if domain in self.blocklist:
            is_blocked = True
            threat_level = "critical"
            reputation_score = 0
            category = URLCategory.MALWARE
            reasons.append(f"Blocklisted: {self.blocklist[domain]}")
        
        # Check database blocklist
        if not is_blocked:
            try:
                from . import database as db
                # Check exact domain first
                db_blocklist = db.get_blocklist()
                
                # Normalize domain for comparison (already done above, but being extra safe)
                normalized_domain = domain.lower().strip()
                
                print(f"DEBUG: Analyzing URL '{url}', extracted domain '{normalized_domain}'")
                
                # Check for exact match or parent matches
                check_domain = normalized_domain
                while True:
                    if check_domain in db_blocklist:
                        is_blocked = True
                        threat_level = "critical"
                        reputation_score = 0
                        reason = db_blocklist[check_domain]
                        if reason.startswith("Category: "):
                            category = reason.replace("Category: ", "")
                        else:
                            category = URLCategory.MALWARE
                        reasons.append(f"Blocklisted: {reason}")
                        print(f"DEBUG: MATCH FOUND in blocklist for '{check_domain}' (Reason: {reason})")
                        break
                    
                    if '.' not in check_domain:
                        break
                    check_domain = check_domain.split('.', 1)[1]
                    if not check_domain:
                        break
                
                if not is_blocked:
                    print(f"DEBUG: No blocklist match found for '{normalized_domain}' in {len(db_blocklist)} domains")
                    
            except Exception as e:
                print(f"DEBUG ERROR: Database check failed: {e}")
                logger.error(f"Could not check database blocklist: {e}", exc_info=True)
        
        # Check suspicious patterns
        pattern_match = self._check_suspicious_patterns(url)
        if pattern_match:
            threat_level = self._elevate_threat_level(threat_level, "medium")
            reputation_score = max(0, reputation_score - 30)
            reasons.append(f"Matches suspicious pattern: {pattern_match}")
        
        # If blocked from database, set the status
        if is_blocked:
            threat_level = "critical"
            reputation_score = 0
            reasons.append(f"🚫 Blocked - Domain is in category: {category}")
        else:
            # Domain not in blocklist = Safe
            threat_level = "safe"
            reputation_score = 100
            reasons.append("✅ Domain not found in any blocked category - Safe to access")
        
        # Categorize domain
        if category == URLCategory.UNKNOWN:
            category = self._categorize_domain(domain)
        
        # Create result
        result = URLAnalysisResult(
            url=url,
            domain=domain,
            is_blocked=is_blocked,
            category=category,
            threat_level=threat_level,
            reputation_score=reputation_score,
            reasons=reasons if reasons else ["No threats detected"],
            safe_browsing_result=safe_browsing_result,
            analysis_timestamp=datetime.utcnow().isoformat()
        )
        
        # Cache result (DISABLED)
        # self.cache[cache_key] = (result, datetime.now())
        
        return result
    
    def _categorize_domain(self, domain: str) -> str:
        """Categorize a domain based on patterns."""
        for category, patterns in self.CATEGORY_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, domain, re.IGNORECASE):
                    return category
        return URLCategory.UNKNOWN
    
    def _check_suspicious_patterns(self, url: str) -> Optional[str]:
        """Check URL against suspicious patterns."""
        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                return pattern
        return None
    
    def _is_allowlisted(self, domain: str) -> bool:
        """Check if domain is in allowlist."""
        for allowed in self.allowlist:
            if domain == allowed or domain.endswith('.' + allowed):
                return True
        return False
    
    def _elevate_threat_level(self, current: str, new: str) -> str:
        """Elevate threat level if new is higher."""
        levels = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        if levels.get(new, 0) > levels.get(current, 0):
            return new
        return current
    
    def _check_google_safe_browsing(self, url: str) -> Optional[Dict[str, Any]]:
        """Check URL against Google Safe Browsing API."""
        if not self.google_api_key:
            return None
        
        try:
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.google_api_key}"
            
            body = {
                "client": {
                    "clientId": "ransomguard",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            response = requests.post(api_url, json=body, timeout=5)
            
            if response.status_code == 200:
                return response.json()
            
        except Exception as e:
            logger.error(f"Google Safe Browsing API error: {e}")
        
        return None
    
    def _check_urlhaus(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Check URL against URLhaus API (abuse.ch) for malware detection.
        FREE API - No key required.
        """
        try:
            api_url = "https://urlhaus-api.abuse.ch/v1/url/"
            response = requests.post(
                api_url,
                data={"url": url},
                timeout=5,
                headers={"Accept": "application/json"}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok":
                    return {
                        "found": True,
                        "threat_type": data.get("threat", "malware"),
                        "tags": data.get("tags", []),
                        "url_status": data.get("url_status", "unknown"),
                        "date_added": data.get("date_added"),
                        "source": "URLhaus"
                    }
                elif data.get("query_status") == "no_results":
                    return {"found": False, "source": "URLhaus"}
            
        except requests.Timeout:
            logger.warning("URLhaus API timeout")
        except Exception as e:
            logger.error(f"URLhaus API error: {e}")
        
        return None
    
    def _check_phishtank(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Check URL against PhishTank for phishing detection.
        FREE API - No key required (but rate limited).
        """
        try:
            # PhishTank API endpoint
            api_url = "https://checkurl.phishtank.com/checkurl/"
            
            response = requests.post(
                api_url,
                data={
                    "url": url,
                    "format": "json"
                },
                timeout=5,
                headers={
                    "User-Agent": "phishtank/ransomguard"
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                results = data.get("results", {})
                if results.get("in_database"):
                    return {
                        "found": True,
                        "is_phish": results.get("valid", False),
                        "verified": results.get("verified", False),
                        "verified_at": results.get("verified_at"),
                        "source": "PhishTank"
                    }
                else:
                    return {"found": False, "source": "PhishTank"}
                    
        except requests.Timeout:
            logger.warning("PhishTank API timeout")
        except Exception as e:
            logger.error(f"PhishTank API error: {e}")
        
        return None
    
    def _check_all_threat_apis(self, url: str, domain: str) -> Dict[str, Any]:
        """
        Check URL against all available threat intelligence APIs.
        Returns aggregated threat information.
        """
        threats_found = []
        threat_score = 0
        threat_sources = []
        
        # Check URLhaus (Malware)
        urlhaus_result = self._check_urlhaus(url)
        if urlhaus_result and urlhaus_result.get("found"):
            threats_found.append({
                "source": "URLhaus",
                "type": urlhaus_result.get("threat_type", "malware"),
                "tags": urlhaus_result.get("tags", []),
                "status": urlhaus_result.get("url_status")
            })
            threat_score += 50
            threat_sources.append("URLhaus (Malware)")
        
        # Check PhishTank (Phishing)
        phishtank_result = self._check_phishtank(url)
        if phishtank_result and phishtank_result.get("found") and phishtank_result.get("is_phish"):
            threats_found.append({
                "source": "PhishTank",
                "type": "phishing",
                "verified": phishtank_result.get("verified", False)
            })
            threat_score += 40 if phishtank_result.get("verified") else 30
            threat_sources.append("PhishTank (Phishing)")
        
        # Check Google Safe Browsing (if API key available)
        if self.google_api_key:
            gsb_result = self._check_google_safe_browsing(url)
            if gsb_result and gsb_result.get("matches"):
                for match in gsb_result["matches"]:
                    threats_found.append({
                        "source": "Google Safe Browsing",
                        "type": match.get("threatType", "unknown").lower(),
                        "platform": match.get("platformType")
                    })
                    threat_score += 50
                    threat_sources.append("Google Safe Browsing")
        
        return {
            "threats_found": threats_found,
            "threat_score": min(threat_score, 100),
            "threat_sources": threat_sources,
            "is_malicious": len(threats_found) > 0,
            "checked_apis": ["URLhaus", "PhishTank"] + (["Google Safe Browsing"] if self.google_api_key else [])
        }
    
    def add_to_blocklist(self, domain: str, reason: str = "Manually blocked"):
        """Add a domain to the blocklist and persist to database."""
        domain = domain.lower().strip()
        self.blocklist[domain] = reason
        try:
            from . import database as db
            db.add_to_blocklist(domain, reason)
        except Exception as e:
            logger.error(f"Error persisting blocklist: {e}")
    
    def remove_from_blocklist(self, domain: str):
        """Remove a domain from the blocklist."""
        domain = domain.lower().strip()
        self.blocklist.pop(domain, None)
        try:
            from . import database as db
            db.remove_from_blocklist(domain)
        except Exception as e:
            logger.error(f"Error removing from blocklist: {e}")
    
    def add_to_allowlist(self, domain: str):
        """Add a domain to the allowlist."""
        domain = domain.lower().strip()
        if domain not in self.allowlist:
            self.allowlist.append(domain)
            try:
                from . import database as db
                db.add_to_allowlist(domain)
            except Exception as e:
                logger.error(f"Error persisting allowlist: {e}")
    
    def remove_from_allowlist(self, domain: str):
        """Remove a domain from the allowlist."""
        domain = domain.lower().strip()
        try:
            self.allowlist.remove(domain)
            from . import database as db
            # Assuming db.remove_from_allowlist exists or similar
            # If not, it won't crash due to the try-except
            if hasattr(db, 'remove_from_allowlist'):
                db.remove_from_allowlist(domain)
        except (ValueError, Exception):
            pass
    
    def get_blocklist(self) -> Dict[str, str]:
        """Get current blocklist."""
        return self.blocklist.copy()
    
    def get_allowlist(self) -> List[str]:
        """Get current allowlist."""
        return self.allowlist.copy()


class CategoryBlocker:
    """Block URLs by category."""
    
    def __init__(self):
        self.blocked_categories: List[str] = []
    
    def block_category(self, category: str):
        """Block a URL category."""
        if category not in self.blocked_categories:
            self.blocked_categories.append(category)
    
    def unblock_category(self, category: str):
        """Unblock a URL category."""
        try:
            self.blocked_categories.remove(category)
        except ValueError:
            pass
    
    def is_category_blocked(self, category: str) -> bool:
        """Check if a category is blocked."""
        return category in self.blocked_categories
    
    def get_blocked_categories(self) -> List[str]:
        """Get list of blocked categories."""
        return self.blocked_categories.copy()


# Global instances
url_filter = URLFilter()
category_blocker = CategoryBlocker()


def analyze_url(url: str) -> Dict[str, Any]:
    """
    Main function to analyze a URL.
    
    Args:
        url: URL to analyze
        
    Returns:
        Dictionary with analysis results
    """
    result = url_filter.analyze_url(url)
    
    # Check category blocking
    if category_blocker.is_category_blocked(result.category):
        result.is_blocked = True
        result.reasons.append(f"Category '{result.category}' is blocked")
    
    return asdict(result)


def get_all_categories() -> List[str]:
    """Get all available URL categories."""
    return [
        URLCategory.MALWARE, URLCategory.PHISHING, URLCategory.ADULT,
        URLCategory.GAMBLING, URLCategory.SOCIAL_MEDIA, URLCategory.STREAMING,
        URLCategory.GAMING, URLCategory.SHOPPING, URLCategory.NEWS,
        URLCategory.BUSINESS, URLCategory.EDUCATION, URLCategory.GOVERNMENT,
        URLCategory.SAFE, URLCategory.UNKNOWN
    ]

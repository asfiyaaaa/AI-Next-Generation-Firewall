"""
Anti-Bot and DNS Security Module
Provides bot detection, rate limiting, CAPTCHA, and DNS filtering.
"""

import re
import time
import hashlib
import logging
import random
import string
import io
import base64
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from collections import defaultdict
from PIL import Image, ImageDraw, ImageFont
import sqlite3
import os

logger = logging.getLogger(__name__)


@dataclass
class BotResult:
    is_bot: bool
    confidence: float
    reason: str
    ip: str
    timestamp: str
    action: str  # 'allow', 'block', 'captcha'
    headers_analyzed: int
    challenge_id: Optional[str] = None
    captcha_image: Optional[str] = None


@dataclass
class DNSQueryResult:
    domain: str
    is_blocked: bool
    category: str
    threat_level: str
    resolved_ips: List[str]
    ttl: int
    query_time_ms: float


class BotDetector:
    BOT_USER_AGENTS = ["bot", "crawler", "spider", "scraper", "curl", "wget", "python-requests"]
    LEGITIMATE_BOTS = ["googlebot", "bingbot", "yandexbot", "duckduckbot"]
    
    def __init__(self):
        self.request_history: Dict[str, List[float]] = defaultdict(list)
        self.blocked_ips: Dict[str, datetime] = {}
        
    def analyze_request(self, ip_address: str, user_agent: str, headers: Dict[str, str],
                       cookies: Dict[str, str] = None, js_enabled: bool = True) -> BotResult:
        reasons, bot_score, bot_type = [], 0.0, "human"
        
        if ip_address in self.blocked_ips:
            if datetime.now() < self.blocked_ips[ip_address]:
                # IP is temporarily blocked
                action = "block"
                reason = "IP temporarily blocked"
                confidence = 1.0
                is_bot = True
                logger.info(f"Bot analysis for {ip_address}: {action.upper()} (Conf: {confidence}%, Reason: {reason})")
                return BotResult(ip_address=ip_address, is_bot=is_bot, confidence=confidence, reason=reason,
                                 timestamp=datetime.now().isoformat(), action=action, headers_analyzed=len(headers))
            del self.blocked_ips[ip_address]
        
        ua_lower = user_agent.lower()
        for bot_ua in self.BOT_USER_AGENTS:
            if bot_ua in ua_lower:
                reasons.append(f"Bot UA: {bot_ua}")
                bot_score += 0.4
                bot_type = "automated"
                break
        
        for legit in self.LEGITIMATE_BOTS:
            if legit in ua_lower:
                # Legitimate bot, allow but mark as bot
                action = "allow"
                reason = f"Search engine: {legit}"
                confidence = 0.9
                is_bot = True
                logger.info(f"Bot analysis for {ip_address}: {action.upper()} (Conf: {confidence}%, Reason: {reason})")
                return BotResult(ip_address=ip_address, is_bot=is_bot, confidence=confidence, reason=reason,
                                 timestamp=datetime.now().isoformat(), action=action, headers_analyzed=len(headers))
        
        current_time = time.time()
        self.request_history[ip_address].append(current_time)
        self.request_history[ip_address] = [t for t in self.request_history[ip_address] if current_time - t < 60]
        
        if len(self.request_history[ip_address]) > 50:
            reasons.append(f"High rate: {len(self.request_history[ip_address])}/min")
            bot_score += 0.3
        
        if not reasons: reasons.append("No bot indicators")

        is_bot = bot_score >= 0.5
        confidence = min(bot_score, 1.0)
        reason = ", ".join(reasons)

        action = "allow"
        if bot_score >= 0.8:
            action = "block"
        elif 0.3 <= bot_score < 0.8:
            action = "captcha"
        
        # Forensic logging
        logger.info(f"Bot analysis for {ip_address}: {action.upper()} (Conf: {confidence}%, Reason: {reason})")
        
        challenge_id = None
        captcha_image = None
        
        if action == "captcha":
            challenge = captcha_manager.generate_challenge(ip_address)
            challenge_id = challenge["challenge_id"]
            captcha_image = challenge["image"]
        
        return BotResult(
            ip=ip_address,
            is_bot=is_bot,
            confidence=confidence,
            reason=reason,
            timestamp=datetime.now().isoformat(),
            action=action,
            headers_analyzed=len(headers),
            challenge_id=challenge_id,
            captcha_image=captcha_image
        )
    
    def reset_history(self, ip_address: str):
        """Reset request history for an IP after successful CAPTCHA."""
        if ip_address in self.request_history:
            self.request_history[ip_address] = []
        if ip_address in self.blocked_ips:
            del self.blocked_ips[ip_address]
        logger.info(f"Bot detection history reset for verified IP: {ip_address}")
    
    def block_ip(self, ip_address: str, minutes: int = 30):
        self.blocked_ips[ip_address] = datetime.now() + timedelta(minutes=minutes)


class RateLimiter:
    def __init__(self, rpm: int = 60, burst: int = 10, block_mins: int = 15):
        self.rpm, self.burst, self.block_mins = rpm, burst, block_mins
        self.entries: Dict[str, Dict] = {}
    
    def check(self, ip: str) -> Tuple[bool, Optional[str]]:
        now = time.time()
        if ip not in self.entries:
            self.entries[ip] = {"count": 1, "first": now, "last": now, "blocked": False}
            return True, None
        
        e = self.entries[ip]
        if e["blocked"]:
            if e.get("until", 0) > now: return False, "Blocked"
            e["blocked"], e["count"], e["first"] = False, 0, now
        
        if now - e["first"] > 60:
            e["count"], e["first"] = 1, now
            return True, None
        
        e["count"] += 1
        e["last"] = now
        if e["count"] > self.rpm:
            e["blocked"], e["until"] = True, now + self.block_mins * 60
            return False, f"Rate limit exceeded ({self.rpm}/min)"
        return True, None


class DNSFilter:
    """Forensic-grade DNS filtering and categorization."""
    
    def __init__(self):
        # Category-based blocklist
        self.categories = {
            "malware": ["malware-distribution.com", "c2-server.top", "ransomware.bad"],
            "phishing": ["secure-paypal-login.xyz", "phishing-bank.com", "update-microsoft.host"],
            "crypto_scam": ["btc-scam-reward.xyz", "mining-pool.work"],
            "illegal": ["darknet-market.click"],
            "adware": ["ad-tracker.net"]
        }
        self.blocked_categories = set(["malware", "phishing", "crypto_scam"])
    
    def resolve(self, domain: str) -> DNSQueryResult:
        """Resolve domain and check against forensic blocklists."""
        domain = domain.lower().strip()
        start = time.time()
        
        is_blocked = False
        category = "clean"
        threat_level = "safe"
        
        # Check categories
        for cat, domains in self.categories.items():
            if domain in domains:
                category = cat
                if cat in self.blocked_categories:
                    is_blocked = True
                break
        
        # If still clean, use Threat Intelligence engine
        if category == "clean":
            intel = threat_intel.analyze(domain)
            if intel.is_suspicious or (intel.categories and intel.categories[0] != "clean"):
                category = intel.categories[0] if intel.categories else "suspicious"
                # If adult or critical threat, we can decide to block or just categorize
                if category in ["malware", "phishing", "ransomware", "C2", "adult_content"]:
                    if category in self.blocked_categories or category == "adult_content": # Block adult too if configured
                         is_blocked = True
        
        # Determine threat level
        if is_blocked:
            threat_level = "critical" if category in ["malware", "phishing"] else "high"
        
        resolved_ips = []
        try:
            # Real resolution
            import socket
            resolved_ips = [socket.gethostbyname(domain)]
        except:
            pass
            
        return DNSQueryResult(
            domain=domain,
            is_blocked=is_blocked,
            category=category,
            threat_level=threat_level,
            resolved_ips=resolved_ips,
            ttl=3600,
            query_time_ms=round((time.time() - start) * 1000, 2)
        )
    
    def add_block(self, domain: str, cat: str = "manual"): self.blocklist[domain.lower()] = cat
    def remove_block(self, domain: str): self.blocklist.pop(domain.lower(), None)


class CaptchaGenerator:
    """Generates real image-based CAPTCHAs."""
    
    def __init__(self, width: int = 200, height: int = 70):
        self.width = width
        self.height = height
        self.font_size = 36

    def generate(self) -> Tuple[str, str]:
        """Generate a random text and its image representation (base64)."""
        # Generate random 6-character alphanum string
        text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        
        # Create image with dark background
        image = Image.new('RGB', (self.width, self.height), color=(28, 30, 38))
        draw = ImageDraw.Draw(image)
        
        # Attempt to load a font, fallback to default
        try:
            # Try some common windows fonts
            font = ImageFont.truetype("arial.ttf", self.font_size)
        except:
            font = ImageFont.load_default()

        # Add some noise (lines)
        for _ in range(10):
            x1 = random.randint(0, self.width)
            y1 = random.randint(0, self.height)
            x2 = random.randint(0, self.width)
            y2 = random.randint(0, self.height)
            draw.line([(x1, y1), (x2, y2)], fill=(60, 60, 80), width=1)

        # Draw text with slight random offsets
        current_x = 20
        for char in text:
            offset_y = random.randint(10, 25)
            # Use color that fits the theme (e.g., secondary purple)
            draw.text((current_x, offset_y), char, font=font, fill=(112, 128, 255))
            current_x += 30

        # Add noise (dots)
        for _ in range(500):
            draw.point((random.randint(0, self.width), random.randint(0, self.height)), fill=(100, 100, 100))

        # Save to buffer
        buf = io.BytesIO()
        image.save(buf, format='PNG')
        img_str = base64.b64encode(buf.getvalue()).decode()
        
        return text, f"data:image/png;base64,{img_str}"


class CaptchaManager:
    """Manages forensic-grade CAPTCHA challenges and verification."""
    
    def __init__(self):
        self.generator = CaptchaGenerator()
        self.challenges: Dict[str, Dict] = {}
        self.ttl = 300  # 5 minutes
    
    def generate_challenge(self, ip: str) -> Dict[str, Any]:
        """Generate a new forensic CAPTCHA challenge."""
        text, image_b64 = self.generator.generate()
        cid = hashlib.sha256(f"{ip}{time.time()}{text}".encode()).hexdigest()[:16]
        
        self.challenges[cid] = {
            "ip": ip,
            "text": text,
            "created": time.time(),
            "solved": False
        }
        
        # Log for forensics (text is stored securely on backend)
        logger.info(f"CAPTCHA generated for IP {ip}: CID={cid}")
        
        return {
            "challenge_id": cid,
            "image": image_b64,
            "instruction": "Enter the 6-character code shown above to verify you are human."
        }
    
    def verify(self, cid: str, user_input: str) -> bool:
        """Verify the user's CAPTCHA response."""
        if cid not in self.challenges:
            return False
            
        challenge = self.challenges[cid]
        
        # Check expiry
        if time.time() - challenge["created"] > self.ttl:
            del self.challenges[cid]
            return False
            
        # Case-insensitive match
        is_correct = user_input.strip().upper() == challenge["text"].upper()
        
        if is_correct:
            challenge["solved"] = True
            logger.info(f"CAPTCHA solved correctly for CID={cid}")
            # We keep it for a short time to verify the next request
        else:
            logger.warning(f"Invalid CAPTCHA attempt for CID={cid}: '{user_input}'")
            
        return is_correct


@dataclass
class WhoisResult:
    """WHOIS lookup result for domain investigation."""
    domain: str
    registrar: str
    creation_date: str
    expiration_date: str
    updated_date: str
    registrant_name: str
    registrant_org: str
    registrant_country: str
    registrant_email: str
    name_servers: List[str]
    status: List[str]
    dnssec: str
    raw_text: str
    lookup_time_ms: float
    error: str = ""


class WhoisLookup:
    """WHOIS lookup for cybercrime domain investigation."""
    
    def __init__(self):
        self.cache: Dict[str, Dict] = {}
        self.cache_ttl = 3600  # 1 hour cache
    
    def lookup(self, domain: str) -> WhoisResult:
        """Perform WHOIS lookup on a domain."""
        start = time.time()
        domain = domain.lower().strip()
        
        # Remove protocol and path if present
        if "://" in domain:
            domain = domain.split("://")[1]
        domain = domain.split("/")[0]
        
        # Check cache
        if domain in self.cache:
            cached = self.cache[domain]
            if time.time() - cached.get("timestamp", 0) < self.cache_ttl:
                cached["data"].lookup_time_ms = round((time.time() - start) * 1000, 2)
                return cached["data"]
        
        try:
            import socket
            import subprocess
            
            # Try using system whois command
            result = subprocess.run(
                ["whois", domain],
                capture_output=True,
                text=True,
                timeout=15
            )
            raw_text = result.stdout
            
            # Parse WHOIS response
            whois_data = self._parse_whois(domain, raw_text)
            whois_data.lookup_time_ms = round((time.time() - start) * 1000, 2)
            
            # Cache result
            self.cache[domain] = {"data": whois_data, "timestamp": time.time()}
            
            return whois_data
            
        except FileNotFoundError:
            # whois command not available, use socket approach
            return self._socket_whois(domain, start)
        except subprocess.TimeoutExpired:
            return WhoisResult(
                domain=domain, registrar="", creation_date="", expiration_date="",
                updated_date="", registrant_name="", registrant_org="", 
                registrant_country="", registrant_email="", name_servers=[],
                status=[], dnssec="", raw_text="",
                lookup_time_ms=round((time.time() - start) * 1000, 2),
                error="WHOIS lookup timed out"
            )
        except Exception as e:
            return WhoisResult(
                domain=domain, registrar="", creation_date="", expiration_date="",
                updated_date="", registrant_name="", registrant_org="", 
                registrant_country="", registrant_email="", name_servers=[],
                status=[], dnssec="", raw_text="",
                lookup_time_ms=round((time.time() - start) * 1000, 2),
                error=str(e)
            )
    
    def _socket_whois(self, domain: str, start: float) -> WhoisResult:
        """Fallback WHOIS using direct socket connection."""
        import socket
        
        try:
            # Determine WHOIS server based on TLD
            tld = domain.split(".")[-1]
            whois_servers = {
                "com": "whois.verisign-grs.com",
                "net": "whois.verisign-grs.com",
                "org": "whois.pir.org",
                "io": "whois.nic.io",
                "in": "whois.registry.in",
                "co": "whois.nic.co",
            }
            whois_server = whois_servers.get(tld, f"whois.nic.{tld}")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((whois_server, 43))
            sock.send(f"{domain}\r\n".encode())
            
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            sock.close()
            
            raw_text = response.decode("utf-8", errors="ignore")
            whois_data = self._parse_whois(domain, raw_text)
            whois_data.lookup_time_ms = round((time.time() - start) * 1000, 2)
            
            return whois_data
            
        except Exception as e:
            return WhoisResult(
                domain=domain, registrar="", creation_date="", expiration_date="",
                updated_date="", registrant_name="", registrant_org="", 
                registrant_country="", registrant_email="", name_servers=[],
                status=[], dnssec="", raw_text="",
                lookup_time_ms=round((time.time() - start) * 1000, 2),
                error=f"Socket WHOIS failed: {str(e)}"
            )
    
    def _parse_whois(self, domain: str, raw_text: str) -> WhoisResult:
        """Parse WHOIS response text."""
        def extract(pattern: str, text: str, multi: bool = False) -> Any:
            matches = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
            if multi:
                return list(set(matches)) if matches else []
            return matches[0].strip() if matches else ""
        
        return WhoisResult(
            domain=domain,
            registrar=extract(r"Registrar:\s*(.+)", raw_text) or 
                      extract(r"Registrar Name:\s*(.+)", raw_text),
            creation_date=extract(r"Creation Date:\s*(.+)", raw_text) or
                          extract(r"Created Date:\s*(.+)", raw_text) or
                          extract(r"Registration Date:\s*(.+)", raw_text),
            expiration_date=extract(r"(?:Registry )?Expir(?:y|ation) Date:\s*(.+)", raw_text),
            updated_date=extract(r"Updated Date:\s*(.+)", raw_text) or
                         extract(r"Last Updated:\s*(.+)", raw_text),
            registrant_name=extract(r"Registrant Name:\s*(.+)", raw_text),
            registrant_org=extract(r"Registrant Organi[sz]ation:\s*(.+)", raw_text),
            registrant_country=extract(r"Registrant Country:\s*(.+)", raw_text),
            registrant_email=extract(r"Registrant Email:\s*(.+)", raw_text) or
                             extract(r"Abuse Contact Email:\s*(.+)", raw_text),
            name_servers=extract(r"Name Server:\s*(.+)", raw_text, multi=True),
            status=extract(r"(?:Domain )?Status:\s*(.+)", raw_text, multi=True),
            dnssec=extract(r"DNSSEC:\s*(.+)", raw_text),
            raw_text=raw_text[:5000],  # Limit raw text size
            lookup_time_ms=0
        )


@dataclass
class ThreatIntelResult:
    """Threat intelligence scoring result."""
    domain: str
    threat_score: int  # 0-100
    risk_level: str  # critical, high, medium, low, safe
    categories: List[str]
    indicators: List[str]
    first_seen: str
    last_seen: str
    malware_families: List[str]
    is_suspicious: bool
    recommendation: str


class ThreatIntelligence:
    """Threat Intelligence scoring for domain investigation."""
    
    # Known malicious indicators
    MALICIOUS_TLDS = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'click', 'buzz']
    SUSPICIOUS_KEYWORDS = ['login', 'secure', 'account', 'verify', 'update', 'bank', 'paypal', 
                          'amazon', 'microsoft', 'apple', 'google', 'facebook', 'netflix']
    MALWARE_FAMILIES = ['emotet', 'trickbot', 'dridex', 'cobalt', 'ryuk', 'maze', 'revil', 
                        'lockbit', 'conti', 'darkside']
    HIGH_RISK_COUNTRIES = ['RU', 'CN', 'KP', 'IR', 'NG', 'RO', 'UA', 'BY']
    
    # Content Filtering Keywords
    ADULT_KEYWORDS = ['adult', 'porn', 'sex', 'sexy', 'xxx', 'video', 'tube', 'xhamster', 'pornhub', 'xnxx', 'spankbang']
    GAMBLING_KEYWORDS = ['casino', 'bet', 'poker', 'gambling', 'slot', 'lottery', 'crypto-jackpot']
    
    # Expanded Threat Intelligence Database (Real-Time Forensics)
    KNOWN_THREATS = {
        'malware.testsite.com': {'score': 95, 'type': 'malware', 'family': 'emotet'},
        'phishing-bank.com': {'score': 90, 'type': 'phishing', 'family': None},
        'ransomware.bad': {'score': 100, 'type': 'ransomware', 'family': 'ryuk'},
        'c2-server.top': {'score': 98, 'type': 'C2', 'family': 'trickbot'},
        'update-microsoft.host': {'score': 85, 'type': 'phishing', 'family': None},
        'secure-paypal-login.xyz': {'score': 92, 'type': 'phishing', 'family': None},
        'darknet-market.click': {'score': 80, 'type': 'illegal', 'family': None},
        'btc-scam-reward.xyz': {'score': 88, 'type': 'scam', 'family': None},
        'mining-pool.work': {'score': 75, 'type': 'cryptomining', 'family': None},
    }
    
    def __init__(self):
        self.cache: Dict[str, Dict] = {}
        self.reported_domains: Dict[str, Dict] = {}
        self._load_external_db()
    
    def _load_external_db(self):
        """Load domains from external security.db if available."""
        db_path = os.path.join(os.getcwd(), 'security.db')
        if os.path.exists(db_path):
            try:
                conn = sqlite3.connect(db_path)
                cur = conn.cursor()
                cur.execute("SELECT domain, reason FROM url_blocklist")
                rows = cur.fetchall()
                for domain, reason in rows:
                    if domain:
                        # Map reason to a standard type if possible, else use reason
                        category = reason.lower() if reason else 'blocked'
                        if 'phishing' in category: category = 'phishing'
                        elif 'malware' in category: category = 'malware'
                        
                        self.KNOWN_THREATS[domain.lower()] = {
                            'score': 95, 
                            'type': category, 
                            'family': None
                        }
                logger.info(f"Successfully loaded {len(rows)} domains from security.db")
                conn.close()
            except Exception as e:
                logger.error(f"Error loading security.db: {e}")
    
    def analyze(self, domain: str, whois_data: dict = None, dns_data: dict = None) -> ThreatIntelResult:
        """Analyze domain for threat indicators."""
        domain = domain.lower().strip()
        if "://" in domain:
            domain = domain.split("://")[1]
        domain = domain.split("/")[0]
        
        score = 0
        indicators = []
        categories = []
        malware_families = []
        
        # Check known threats database
        if domain in self.KNOWN_THREATS:
            known = self.KNOWN_THREATS[domain]
            return ThreatIntelResult(
                domain=domain,
                threat_score=known['score'],
                risk_level='critical' if known['score'] >= 80 else 'high',
                categories=[known['type']],
                indicators=['Known threat in database'],
                first_seen=datetime.utcnow().isoformat(),
                last_seen=datetime.utcnow().isoformat(),
                malware_families=[known['family']] if known['family'] else [],
                is_suspicious=True,
                recommendation='BLOCK IMMEDIATELY - Known malicious domain'
            )
        
        # TLD Analysis
        tld = domain.split('.')[-1]
        if tld in self.MALICIOUS_TLDS:
            score += 25
            indicators.append(f'High-risk TLD: .{tld}')
            categories.append('suspicious_tld')
        
        # Keyword Analysis
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in domain and keyword not in domain.split('.')[-2]:
                score += 15
                indicators.append(f'Suspicious keyword: {keyword}')
                categories.append('phishing_keywords')
                break
        
        # Adult Content Analysis
        for keyword in self.ADULT_KEYWORDS:
            if keyword in domain:
                score += 30
                indicators.append(f'Adult content keyword: {keyword}')
                categories.append('adult_content')
                break

        # Gambling Analysis
        for keyword in self.GAMBLING_KEYWORDS:
            if keyword in domain:
                score += 25
                indicators.append(f'Gambling keyword: {keyword}')
                categories.append('gambling_content')
                break
        
        # Pattern Analysis
        if re.search(r'\d{4,}', domain):  # Long numbers
            score += 10
            indicators.append('Contains long numeric sequences')
        
        if len(domain.replace('.', '')) > 50:  # Very long domain
            score += 10
            indicators.append('Unusually long domain name')
        
        if domain.count('-') > 3:  # Many hyphens
            score += 15
            indicators.append('Many hyphens in domain')
            categories.append('suspicious_pattern')
        
        # Brand Spoofing Analysis
        for brand in ['google', 'microsoft', 'apple', 'amazon', 'paypal', 'facebook', 'bank', 'chase', 'wells', 'crypto']:
            if brand in domain and f'{brand}.com' not in domain and f'{brand}.net' not in domain:
                score += 35
                indicators.append(f'CRITICAL: Brand impersonation detected: {brand.upper()}')
                categories.append('brand_spoofing')
                break
        
        # DGA (Domain Generation Algorithm) Detection - Entropy Analysis
        import math
        def get_entropy(s):
            prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
            return - sum([p * math.log(p) / math.log(2.0) for p in prob])
        
        domain_name = domain.split('.')[0]
        entropy = get_entropy(domain_name)
        if entropy > 3.8 and len(domain_name) > 12:
            score += 25
            indicators.append(f'DGA Indicator: High domain entropy ({entropy:.2f})')
            categories.append('dga_detected')
        
        # WHOIS Analysis if available
        if whois_data:
            # Recently registered domain
            if whois_data.get('creation_date'):
                try:
                    created = whois_data['creation_date'][:10]
                    if '2024' in created or '2025' in created:
                        score += 20
                        indicators.append('Recently registered domain')
                        categories.append('newly_registered')
                except:
                    pass
            
            # Privacy protection (suspicious for legitimate sites)
            if whois_data.get('registrant_name', '').lower() in ['redacted', 'privacy', 'private']:
                score += 5
                indicators.append('WHOIS privacy enabled')
            
            # High-risk registrant country
            country = whois_data.get('registrant_country', '').upper()
            if country in self.HIGH_RISK_COUNTRIES:
                score += 20
                indicators.append(f'High-risk country: {country}')
                categories.append('high_risk_location')
        
        # Determine risk level
        if score >= 80:
            risk_level = 'critical'
            recommendation = 'BLOCK - High probability of malicious activity'
        elif score >= 60:
            risk_level = 'high'
            recommendation = 'INVESTIGATE - Multiple threat indicators detected'
        elif score >= 40:
            risk_level = 'medium'
            recommendation = 'MONITOR - Some suspicious indicators present'
        elif score >= 20:
            risk_level = 'low'
            recommendation = 'CAUTION - Minor indicators, likely safe'
        else:
            risk_level = 'safe'
            recommendation = 'ALLOW - No significant threat indicators'
            if not indicators:
                indicators.append('No threat indicators detected')
        
        if not categories:
            categories.append('clean')
        
        return ThreatIntelResult(
            domain=domain,
            threat_score=min(score, 100),
            risk_level=risk_level,
            categories=categories,
            indicators=indicators,
            first_seen=datetime.utcnow().isoformat(),
            last_seen=datetime.utcnow().isoformat(),
            malware_families=malware_families,
            is_suspicious=score >= 40,
            recommendation=recommendation
        )
    
    def report_domain(self, domain: str, category: str, reporter: str = "analyst"):
        """Report a domain as malicious."""
        self.reported_domains[domain.lower()] = {
            'category': category,
            'reporter': reporter,
            'timestamp': datetime.utcnow().isoformat()
        }


@dataclass
class DNSHistoryEntry:
    """DNS query history entry."""
    domain: str
    resolved_ips: List[str]
    query_time: str
    source_ip: str
    category: str
    was_blocked: bool


class DNSHistoryTracker:
    """Track DNS queries for investigation and pattern analysis."""
    
    def __init__(self, max_entries: int = 10000):
        self.history: List[Dict] = []
        self.max_entries = max_entries
        self.domain_stats: Dict[str, Dict] = defaultdict(lambda: {
            'query_count': 0,
            'first_query': None,
            'last_query': None,
            'ips': set(),
            'blocked_count': 0
        })
    
    def record(self, domain: str, ips: List[str], source_ip: str = "unknown", 
               category: str = "unknown", was_blocked: bool = False):
        """Record a DNS query."""
        timestamp = datetime.utcnow().isoformat()
        
        entry = {
            'domain': domain,
            'resolved_ips': ips,
            'query_time': timestamp,
            'source_ip': source_ip,
            'category': category,
            'was_blocked': was_blocked
        }
        
        self.history.append(entry)
        
        # Update domain stats
        stats = self.domain_stats[domain]
        stats['query_count'] += 1
        if not stats['first_query']:
            stats['first_query'] = timestamp
        stats['last_query'] = timestamp
        stats['ips'].update(ips)
        if was_blocked:
            stats['blocked_count'] += 1
        
        # Limit history size
        if len(self.history) > self.max_entries:
            self.history = self.history[-self.max_entries:]
    
    def get_history(self, domain: str = None, limit: int = 100) -> List[Dict]:
        """Get DNS query history."""
        if domain:
            filtered = [h for h in self.history if h['domain'] == domain]
            return filtered[-limit:]
        return self.history[-limit:]
    
    def get_domain_stats(self, domain: str) -> Dict:
        """Get statistics for a specific domain."""
        if domain not in self.domain_stats:
            return {'error': 'Domain not found in history'}
        
        stats = self.domain_stats[domain]
        return {
            'domain': domain,
            'query_count': stats['query_count'],
            'first_query': stats['first_query'],
            'last_query': stats['last_query'],
            'unique_ips': list(stats['ips']),
            'ip_changes': len(stats['ips']),
            'blocked_count': stats['blocked_count'],
            'is_suspicious': len(stats['ips']) > 5 or stats['blocked_count'] > 0
        }
    
    def get_recent_blocked(self, limit: int = 50) -> List[Dict]:
        """Get recently blocked domains."""
        blocked = [h for h in self.history if h['was_blocked']]
        return blocked[-limit:]
    
    def get_suspicious_domains(self, min_queries: int = 10, min_ip_changes: int = 3) -> List[Dict]:
        """Find domains with suspicious patterns."""
        suspicious = []
        for domain, stats in self.domain_stats.items():
            if stats['query_count'] >= min_queries or len(stats['ips']) >= min_ip_changes:
                suspicious.append({
                    'domain': domain,
                    'query_count': stats['query_count'],
                    'ip_changes': len(stats['ips']),
                    'reason': 'High query volume' if stats['query_count'] >= min_queries 
                             else 'Frequent IP changes'
                })
        return sorted(suspicious, key=lambda x: x['query_count'], reverse=True)[:20]


# Global instances
bot_detector = BotDetector()
rate_limiter = RateLimiter()
dns_filter = DNSFilter()
captcha_manager = CaptchaManager()
whois_lookup = WhoisLookup()
threat_intel = ThreatIntelligence()
dns_history = DNSHistoryTracker()

def check_bot(ip: str, ua: str, headers: Dict[str, str], **kw) -> Dict: 
    return asdict(bot_detector.analyze_request(ip, ua, headers, **kw))

def check_rate_limit(ip: str) -> Dict:
    ok, reason = rate_limiter.check(ip)
    return {"allowed": ok, "reason": reason}

def get_captcha_challenge(ip: str) -> Dict:
    """Generate a real image CAPTCHA."""
    return captcha_manager.generate_challenge(ip)

def verify_captcha(cid: str, user_input: str) -> Dict:
    """Verify CAPTCHA and reset bot detector history on success."""
    is_valid = captcha_manager.verify(cid, user_input)
    if is_valid:
        # Get the IP associated with this challenge
        challenge = captcha_manager.challenges.get(cid)
        if challenge:
            bot_detector.reset_history(challenge["ip"])
            
    return {"success": is_valid}

def resolve_dns(domain: str, source_ip: str = "unknown") -> Dict: 
    result = dns_filter.resolve(domain)
    # Track in history
    dns_history.record(domain, result.resolved_ips, source_ip, result.category, result.is_blocked)
    return asdict(result)

def lookup_whois(domain: str) -> Dict:
    """Perform WHOIS lookup for domain investigation."""
    return asdict(whois_lookup.lookup(domain))

def get_threat_intel(domain: str) -> Dict:
    """Get threat intelligence scoring for a domain."""
    whois_data = asdict(whois_lookup.lookup(domain))
    result = threat_intel.analyze(domain, whois_data)
    return asdict(result)

def get_dns_history(domain: str = None, limit: int = 100) -> Dict:
    """Get DNS query history."""
    return {
        'history': dns_history.get_history(domain, limit),
        'total_queries': len(dns_history.history)
    }

def get_dns_domain_stats(domain: str) -> Dict:
    """Get DNS statistics for a domain."""
    return dns_history.get_domain_stats(domain)

def get_suspicious_domains() -> Dict:
    """Get domains with suspicious patterns."""
    return {
        'suspicious': dns_history.get_suspicious_domains(),
        'recent_blocked': dns_history.get_recent_blocked(10)
    }


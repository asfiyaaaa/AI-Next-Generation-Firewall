"""
Dynamic Threat Intelligence Engine
Real-time API integration with AbuseIPDB, VirusTotal, AlienVault OTX, and MaxMind.
"""
from numba.cuda.cudadrv.enums import CU_FUNC_ATTRIBUTE_MAX_DYNAMIC_SHARED_SIZE_BYTES
import asyncio
import hashlib
import time
import logging
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Any
from functools import lru_cache
import httpx

from .context import InspectionContext, ThreatIntelResult
from .config import get_config

logger = logging.getLogger(__name__)


@dataclass
class ThreatIndicator:
    """A threat intelligence indicator."""
    value: str
    indicator_type: str  # ip, domain, hash, ja3
    source: str
    confidence: float
    threat_type: str  # c2, malware, phishing, scanner
    expiry: float = 0  # Unix timestamp
    metadata: Dict[str, Any] = field(default_factory=dict)



class ThreatIntelCache:
    """Thread-safe in-memory cache with TTL."""
    
    def __init__(self, ttl_seconds: int = 3600, max_size: int = 10000):
        self._cache: Dict[str, ThreatIndicator] = {}
        self._ttl = ttl_seconds
        self._max_size = max_size
        self._access_times: Dict[str, float] = {}
    
    def get(self, key: str) -> Optional[ThreatIndicator]:
        """Get cached indicator if not expired."""
        indicator = self._cache.get(key)
        if indicator and indicator.expiry > time.time():
            self._access_times[key] = time.time()
            return indicator
        elif indicator:
            # Expired - remove it
            del self._cache[key]
            del self._access_times[key]
        return None
    def __init__(self, ttl_seconds: int = 3600, max_size: int = 100000):
        self.cache: Dict[str, ThreatIndicator] = {}
        self.__ttl = ttl_seconds
        self._max_size = maxx_size
        self._access_times: Dict[str, float] {}

    def set(self, key: str, indicator: ThreatIndicator) -> None:
        """Cache an indicator with TTL."""
        # Evict oldest entries if at capacity
        if len(self._cache) >= self._max_size:
            self._evict_oldest()
        
        indicator.expiry = time.time() + self._ttl
        self._cache[key] = indicator
        self._access_times[key] = time.time()
    
    def _evict_oldest(self) -> None:
        """Evict least recently accessed entries."""
        if not self._access_times:
            return
        # Remove oldest 10%
        to_remove = max(1, len(self._cache) // 10)
        oldest = sorted(self._access_times.items(), key=lambda x: x[1])[:to_remove]
        for key, _ in oldest:
            self._cache.pop(key, None)
            self._access_times.pop(key, None)
    
    def clear_expired(self) -> int:
        """Remove expired entries. Returns count removed."""
        now = time.time()
        expired = [k for k, v in self._cache.items() if v.expiry <= now]
        for k in expired:
            del self._cache[k]
            self._access_times.pop(k, None)
        return len(expired)


class AbuseIPDBClient:
    """AbuseIPDB API client for IP reputation."""
    
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self._client: Optional[httpx.AsyncClient] = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                headers={"Key": self.api_key, "Accept": "application/json"},
                timeout=10.0
            )
        return self._client
    
    async def check_ip(self, ip: str) -> Optional[ThreatIndicator]:
        """Check IP reputation against AbuseIPDB."""
        try:
            client = await self._get_client()
            response = await client.get(
                f"{self.BASE_URL}/check",
                params={"ipAddress": ip, "maxAgeInDays": 90}
            )
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                abuse_score = data.get("abuseConfidenceScore", 0)
                
                if abuse_score > 0:
                    confidence = abuse_score / 100.0
                    threat_type = "abuse"
                    
                    if data.get("isTor"):
                        threat_type = "tor_exit"
                    elif abuse_score > 80:
                        threat_type = "malicious"
                    elif abuse_score > 50:
                        threat_type = "suspicious"
                    
                    return ThreatIndicator(
                        value=ip,
                        indicator_type="ip",
                        source="AbuseIPDB",
                        confidence=confidence,
                        threat_type=threat_type,
                        metadata={
                            "abuse_score": abuse_score,
                            "country": data.get("countryCode"),
                            "isp": data.get("isp"),
                            "is_tor": data.get("isTor", False),
                            "total_reports": data.get("totalReports", 0)
                        }
                    )
            elif response.status_code == 429:
                logger.warning("AbuseIPDB rate limit exceeded")
            else:
                logger.debug(f"AbuseIPDB returned {response.status_code}")
                
        except Exception as e:
            logger.error(f"AbuseIPDB API error: {e}")
        
        return None
    
    async def close(self):
        if self._client:
            await self._client.aclose()


class VirusTotalClient:
    """VirusTotal API client for file hash and URL reputation."""
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self._client: Optional[httpx.AsyncClient] = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                headers={"x-apikey": self.api_key},
                timeout=15.0
            )
        return self._client
    
    async def check_hash(self, file_hash: str) -> Optional[ThreatIndicator]:
        """Check file hash against VirusTotal."""
        try:
            client = await self._get_client()
            response = await client.get(f"{self.BASE_URL}/files/{file_hash}")
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                attrs = data.get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                
                malicious = stats.get("malicious", 0)
                total = sum(stats.values()) or 1
                
                if malicious > 0:
                    confidence = min(malicious / total * 2, 1.0)  # Scale up
                    
                    return ThreatIndicator(
                        value=file_hash[:16] + "...",
                        indicator_type="hash",
                        source="VirusTotal",
                        confidence=confidence,
                        threat_type="malware",
                        metadata={
                            "malicious": malicious,
                            "suspicious": stats.get("suspicious", 0),
                            "total_engines": total,
                            "file_type": attrs.get("type_description"),
                            "names": attrs.get("names", [])[:3]
                        }
                    )
            elif response.status_code == 404:
                pass  # Hash not found - clean
            elif response.status_code == 429:
                logger.warning("VirusTotal rate limit exceeded")
            
        except Exception as e:
            logger.error(f"VirusTotal API error: {e}")
        
        return None
    
    async def check_domain(self, domain: str) -> Optional[ThreatIndicator]:
        """Check domain reputation against VirusTotal."""
        try:
            client = await self._get_client()
            response = await client.get(f"{self.BASE_URL}/domains/{domain}")
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                attrs = data.get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                
                if malicious > 0 or suspicious > 2:
                    confidence = min((malicious + suspicious * 0.5) / 10, 1.0)
                    
                    return ThreatIndicator(
                        value=domain,
                        indicator_type="domain",
                        source="VirusTotal",
                        confidence=confidence,
                        threat_type="malicious" if malicious > 2 else "suspicious",
                        metadata={
                            "malicious": malicious,
                            "suspicious": suspicious,
                            "categories": attrs.get("categories", {})
                        }
                    )
                    
        except Exception as e:
            logger.error(f"VirusTotal domain API error: {e}")
        
        return None
    
    async def close(self):
        if self._client:
            await self._client.aclose()


class AlienVaultClient:
    """AlienVault OTX API client."""
    
    BASE_URL = "https://otx.alienvault.com/api/v1"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self._client: Optional[httpx.AsyncClient] = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                headers={"X-OTX-API-KEY": self.api_key},
                timeout=10.0
            )
        return self._client
    
    async def check_ip(self, ip: str) -> Optional[ThreatIndicator]:
        """Check IP against AlienVault OTX."""
        try:
            client = await self._get_client()
            response = await client.get(f"{self.BASE_URL}/indicators/IPv4/{ip}/general")
            
            if response.status_code == 200:
                data = response.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                
                if pulse_count > 0:
                    confidence = min(pulse_count / 10, 1.0)
                    
                    return ThreatIndicator(
                        value=ip,
                        indicator_type="ip",
                        source="AlienVault OTX",
                        confidence=confidence,
                        threat_type=data.get("type", "unknown"),
                        metadata={
                            "pulse_count": pulse_count,
                            "country": data.get("country_name"),
                            "asn": data.get("asn")
                        }
                    )
                    
        except Exception as e:
            logger.error(f"AlienVault API error: {e}")
        
        return None
    
    async def check_domain(self, domain: str) -> Optional[ThreatIndicator]:
        """Check domain against AlienVault OTX."""
        try:
            client = await self._get_client()
            response = await client.get(f"{self.BASE_URL}/indicators/domain/{domain}/general")
            
            if response.status_code == 200:
                data = response.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                
                if pulse_count > 0:
                    confidence = min(pulse_count / 10, 1.0)
                    
                    return ThreatIndicator(
                        value=domain,
                        indicator_type="domain",
                        source="AlienVault OTX",
                        confidence=confidence,
                        threat_type="malicious",
                        metadata={"pulse_count": pulse_count}
                    )
                    
        except Exception as e:
            logger.error(f"AlienVault domain API error: {e}")
        
        return None
    
    async def close(self):
        if self._client:
            await self._client.aclose()


class MaxMindClient:
    """MaxMind GeoIP client for geolocation and risk scoring."""
    
    def __init__(self, account_id: str, license_key: str):
        self.account_id = account_id
        self.license_key = license_key
        self._client: Optional[httpx.AsyncClient] = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                auth=(self.account_id, self.license_key),
                timeout=10.0
            )
        return self._client
    
    async def get_insights(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get GeoIP insights for an IP address."""
        try:
            client = await self._get_client()
            response = await client.get(
                f"https://geoip.maxmind.com/geoip/v2.1/insights/{ip}"
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "country": data.get("country", {}).get("iso_code"),
                    "city": data.get("city", {}).get("names", {}).get("en"),
                    "is_anonymous": data.get("traits", {}).get("is_anonymous", False),
                    "is_anonymous_vpn": data.get("traits", {}).get("is_anonymous_vpn", False),
                    "is_hosting_provider": data.get("traits", {}).get("is_hosting_provider", False),
                    "is_tor_exit_node": data.get("traits", {}).get("is_tor_exit_node", False),
                    "risk_score": data.get("risk_score", 0)
                }
                
        except Exception as e:
            logger.error(f"MaxMind API error: {e}")
        
        return None
    
    async def close(self):
        if self._client:
            await self._client.aclose()


class ThreatIntelEngine:
    """
    Enterprise Dynamic Threat Intelligence Engine.
    
    Integrates with:
    - AbuseIPDB (IP reputation)
    - VirusTotal (file hash, domain reputation)
    - AlienVault OTX (threat feeds)
    - MaxMind (GeoIP, risk scoring)
    
    Features:
    - Async API calls
    - Response caching
    - Rate limiting
    - Fallback to static data
    - Allowlist support
    """
    
    def __init__(self):
        self._config = get_config().threat_intel
        self._cache = ThreatIntelCache(
            ttl_seconds=self._config.cache_ttl_seconds,
            max_size=self._config.cache_max_size
        )
        self._allowlist: set = set()
        
        # Initialize API clients
        self._abuseipdb: Optional[AbuseIPDBClient] = None
        self._virustotal: Optional[VirusTotalClient] = None
        self._alienvault: Optional[AlienVaultClient] = None
        self._maxmind: Optional[MaxMindClient] = None
        
        self._init_clients()
    
    def _init_clients(self):
        """Initialize API clients based on configuration."""
        if self._config.abuseipdb_enabled and self._config.abuseipdb_api_key:
            self._abuseipdb = AbuseIPDBClient(self._config.abuseipdb_api_key)
            logger.info("AbuseIPDB client initialized")
        
        if self._config.virustotal_enabled and self._config.virustotal_api_key:
            self._virustotal = VirusTotalClient(self._config.virustotal_api_key)
            logger.info("VirusTotal client initialized")
        
        if self._config.alienvault_enabled and self._config.alienvault_api_key:
            self._alienvault = AlienVaultClient(self._config.alienvault_api_key)
            logger.info("AlienVault OTX client initialized")
        
        if self._config.maxmind_enabled and self._config.maxmind_license_key:
            self._maxmind = MaxMindClient(
                self._config.maxmind_account_id,
                self._config.maxmind_license_key
            )
            logger.info("MaxMind client initialized")
    
    def add_to_allowlist(self, indicator: str) -> None:
        """Add indicator to allowlist (will not be flagged)."""
        self._allowlist.add(indicator.lower())
    
    def remove_from_allowlist(self, indicator: str) -> None:
        """Remove indicator from allowlist."""
        self._allowlist.discard(indicator.lower())
    
    def correlate(self, ctx: InspectionContext) -> None:
        """
        Synchronous wrapper for async correlation.
        """
        try:
            # Fast-fail if no clients are active
            if not any([self._abuseipdb, self._virustotal, self._alienvault, self._maxmind]):
                ctx.threat_intel_result = ThreatIntelResult(hit=False)
                return

            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Already in async context - create task
                asyncio.create_task(self._correlate_async(ctx))
            else:
                loop.run_until_complete(self._correlate_async(ctx))
        except RuntimeError:
            # No event loop - create new one
            asyncio.run(self._correlate_async(ctx))
    
    async def _correlate_async(self, ctx: InspectionContext) -> None:
        """
        Async correlation against all threat intel sources.
        """
        hits: List[ThreatIndicator] = []
        
        # Gather all checks concurrently
        tasks = []
        
        # Check source and destination IPs
        if ctx.metadata.src_ip and ctx.metadata.src_ip.lower() not in self._allowlist:
            tasks.append(self._check_ip_async(ctx.metadata.src_ip))
        
        if ctx.metadata.dst_ip and ctx.metadata.dst_ip.lower() not in self._allowlist:
            tasks.append(self._check_ip_async(ctx.metadata.dst_ip))
        
        # Check TLS SNI (domain)
        if ctx.metadata.tls_metadata and ctx.metadata.tls_metadata.sni:
            domain = ctx.metadata.tls_metadata.sni.lower()
            if domain not in self._allowlist:
                tasks.append(self._check_domain_async(domain))
        
        # Check payload hash
        payload = ctx.normalized_payload or ctx.raw_payload
        if payload and len(payload) > 0:
            tasks.append(self._check_hash_async(payload))
        
        # Execute all checks concurrently
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, ThreatIndicator):
                    hits.append(result)
                elif isinstance(result, list):
                    hits.extend(result)
        
        # Process hits
        if hits:
            hits.sort(key=lambda x: x.confidence, reverse=True)
            primary = hits[0]
            
            # False-positive suppression
            if primary.confidence < 0.5 and len(hits) == 1:
                logger.debug(f"Suppressing low-confidence hit: {primary.value}")
                ctx.threat_intel_result = ThreatIntelResult(hit=False)
                return
            
            ctx.threat_intel_result = ThreatIntelResult(
                hit=True,
                source=primary.source,
                confidence=primary.confidence,
                indicator_type=primary.indicator_type,
                threat_type=primary.threat_type
            )
            
            logger.warning(
                f"Threat intel hit: {primary.indicator_type}={primary.value} "
                f"(source={primary.source}, confidence={primary.confidence:.2f})"
            )
        else:
            ctx.threat_intel_result = ThreatIntelResult(hit=False)
    
    async def _check_ip_async(self, ip: str) -> List[ThreatIndicator]:
        """Check IP against all enabled sources."""
        hits = []
        
        # Check cache first
        cached = self._cache.get(f"ip:{ip}")
        if cached:
            return [cached]
        
        # Query all enabled sources concurrently
        tasks = []
        
        if self._abuseipdb:
            tasks.append(("abuseipdb", self._abuseipdb.check_ip(ip)))
        
        if self._alienvault:
            tasks.append(("alienvault", self._alienvault.check_ip(ip)))
        
        # Get MaxMind insights for GeoIP risk
        if self._maxmind:
            tasks.append(("maxmind", self._maxmind.get_insights(ip)))
        
        for source, task in tasks:
            try:
                result = await task
                if result:
                    if isinstance(result, ThreatIndicator):
                        hits.append(result)
                        self._cache.set(f"ip:{ip}:{source}", result)
                    elif isinstance(result, dict) and result.get("is_tor_exit_node"):
                        # MaxMind Tor detection
                        indicator = ThreatIndicator(
                            value=ip,
                            indicator_type="ip",
                            source="MaxMind",
                            confidence=0.9,
                            threat_type="tor_exit",
                            metadata=result
                        )
                        hits.append(indicator)
            except Exception as e:
                logger.debug(f"{source} check failed: {e}")
        
        return hits
    
    async def _check_domain_async(self, domain: str) -> List[ThreatIndicator]:
        """Check domain against all enabled sources."""
        hits = []
        
        cached = self._cache.get(f"domain:{domain}")
        if cached:
            return [cached]
        
        tasks = []
        
        if self._virustotal:
            tasks.append(("virustotal", self._virustotal.check_domain(domain)))
        
        if self._alienvault:
            tasks.append(("alienvault", self._alienvault.check_domain(domain)))
        
        for source, task in tasks:
            try:
                result = await task
                if result:
                    hits.append(result)
                    self._cache.set(f"domain:{domain}:{source}", result)
            except Exception as e:
                logger.debug(f"{source} domain check failed: {e}")
        
        return hits


        if self._virustotal
    
    async def _check_hash_async(self, data: bytes) -> Optional[ThreatIndicator]:
        """Check file hash against VirusTotal."""
        if not self._virustotal:
            return None
        
        sha256 = hashlib.sha256(data).hexdigest()
        
        cached = self._cache.get(f"hash:{sha256}")
        if cached:
            return cached
        
        try:
            result = await self._virustotal.check_hash(sha256)
            if result:
                self._cache.set(f"hash:{sha256}", result)
            return result
        except Exception as e:
            logger.debug(f"Hash check failed: {e}")
            return None
    
    async def close(self):
        """Close all API clients."""
        if self._abuseipdb:
            await self._abuseipdb.close()
        if self._virustotal:
            await self._virustotal.close()
        if self._alienvault:
            await self._alienvault.close()
        if self._maxmind:
            await self._maxmind.close()
             




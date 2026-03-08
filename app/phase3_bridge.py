"""
Phase 3 Integration Bridge

Routes reassembled TCP streams to appropriate Phase-3 security modules:
- Malware Detection (ML-based)
- URL Filtering
- Content Filtering
- DNS Security
- Anti-Bot Detection
- Sandboxing

Supports HTTP API integration with the Phase-3 FastAPI backend.
"""
import base64
import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Callable
from queue import Queue, Empty
from concurrent.futures import ThreadPoolExecutor

# Import from TCP Reassembly module
from app.TCP_Reassemble.callbacks import ReassembledStream, Phase3Integration

logger = logging.getLogger(__name__)


@dataclass
class Phase3Config:
    """Configuration for Phase 3 integration."""
    # Connection settings
    api_base_url: str = "http://127.0.0.1:8000"
    timeout_seconds: float = 5.0
    enabled: bool = True
    
    # Processing mode
    async_mode: bool = True  # Non-blocking analysis
    batch_size: int = 10
    batch_timeout_ms: int = 100
    
    # Worker settings
    max_workers: int = 4
    queue_size: int = 10000
    
    # Enabled analyzers
    malware_detection: bool = True
    url_filtering: bool = True
    content_filtering: bool = True
    dns_security: bool = True
    antibot: bool = True
    sandboxing: bool = False  # Expensive, disabled by default
    
    # Logging
    log_all_streams: bool = False
    log_detections_only: bool = True


@dataclass
class AnalysisResult:
    """Result from Phase 3 analysis."""
    stream_id: str
    analyzer: str
    verdict: str  # "allow", "block", "warn"
    confidence: float = 0.0
    reason: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "stream_id": self.stream_id,
            "analyzer": self.analyzer,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "reason": self.reason,
            "details": self.details,
            "timestamp": self.timestamp
        }


class ContentDetector:
    """Detects content type from stream data."""
    
    # HTTP method patterns
    HTTP_METHODS = (b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ', b'OPTIONS ', b'PATCH ')
    HTTP_RESPONSE = b'HTTP/'
    
    # File magic bytes
    PE_HEADER = b'MZ'
    PDF_HEADER = b'%PDF'
    ZIP_HEADER = b'PK'
    GZIP_HEADER = b'\x1f\x8b'
    
    @classmethod
    def detect(cls, data: bytes, app_protocol: Optional[str] = None) -> str:
        """
        Detect content type from stream data.
        
        Returns one of:
        - 'http_request'
        - 'http_response'
        - 'file_download'
        - 'dns_query'
        - 'tls_handshake'
        - 'unknown'
        """
        if not data:
            return 'unknown'
        
        # Check app protocol hint from DPI
        if app_protocol:
            proto_lower = app_protocol.lower()
            if proto_lower in ('http', 'http/1.1', 'http/2'):
                if data.startswith(cls.HTTP_METHODS):
                    return 'http_request'
                elif data.startswith(cls.HTTP_RESPONSE):
                    return 'http_response'
            elif proto_lower == 'dns':
                return 'dns_query'
            elif proto_lower in ('tls', 'ssl', 'https'):
                return 'tls_handshake'
        
        # Check HTTP patterns
        if data.startswith(cls.HTTP_METHODS):
            return 'http_request'
        if data.startswith(cls.HTTP_RESPONSE):
            return 'http_response'
        
        # Check for file downloads (PE, ZIP, PDF)
        if data.startswith(cls.PE_HEADER):
            return 'file_download'
        if data.startswith(cls.PDF_HEADER):
            return 'file_download'
        if data.startswith(cls.ZIP_HEADER):
            return 'file_download'
        if data.startswith(cls.GZIP_HEADER):
            return 'file_download'
        
        # Check DNS (simple heuristic: short data, standard ports)
        if len(data) < 512 and len(data) > 12:
            # Could be DNS, but need port info
            return 'possible_dns'
        
        return 'unknown'
    
    @classmethod
    def extract_urls_from_http(cls, data: bytes) -> List[str]:
        """Extract URLs from HTTP request/response."""
        urls = []
        try:
            text = data.decode('utf-8', errors='ignore')
            
            # Extract from HTTP request line
            match = re.search(r'^(GET|POST|PUT|DELETE|HEAD)\s+(\S+)\s+HTTP', text, re.MULTILINE)
            if match:
                path = match.group(2)
                # Look for Host header
                host_match = re.search(r'Host:\s*(\S+)', text, re.IGNORECASE)
                if host_match:
                    host = host_match.group(1)
                    url = f"http://{host}{path}"
                    urls.append(url)
            
            # Extract URLs from content
            url_pattern = r'https?://[^\s<>"\']+' 
            found = re.findall(url_pattern, text)
            urls.extend(found)
            
        except Exception as e:
            logger.debug(f"URL extraction failed: {e}")
        
        return list(set(urls))  # Deduplicate


class Phase3Bridge(Phase3Integration):
    """
    Bridge between TCP Reassembly and Phase-3 Security Backend.
    
    Routes reassembled streams to appropriate security analyzers
    via HTTP API calls to the Phase-3 FastAPI backend.
    """
    
    def __init__(self, config: Optional[Phase3Config] = None):
        super().__init__(name="Phase3Bridge")
        self.config = config or Phase3Config()
        
        # Statistics
        self.stats = {
            "streams_received": 0,
            "streams_analyzed": 0,
            "http_requests_analyzed": 0,
            "files_analyzed": 0,
            "urls_analyzed": 0,
            "threats_detected": 0,
            "errors": 0,
            "api_calls": 0,
            "api_failures": 0
        }
        
        # Queue for async processing
        self._queue: Queue = Queue(maxsize=self.config.queue_size)
        self._executor: Optional[ThreadPoolExecutor] = None
        self._worker_thread: Optional[threading.Thread] = None
        self._running = False
        
        # HTTP session (lazy init)
        self._session = None
        
        # Start workers if async mode
        if self.config.async_mode and self.config.enabled:
            self._start_workers()
        
        logger.info(f"Phase3Bridge initialized: {self.config.api_base_url} (async={self.config.async_mode})")
    
    def _start_workers(self):
        """Start async worker threads."""
        self._running = True
        self._executor = ThreadPoolExecutor(max_workers=self.config.max_workers)
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker_thread.start()
        logger.info(f"Phase3Bridge workers started: {self.config.max_workers} threads")
    
    def _stop_workers(self):
        """Stop worker threads."""
        self._running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=2.0)
        if self._executor:
            self._executor.shutdown(wait=False)
    
    def _worker_loop(self):
        """Background worker that processes queued streams."""
        while self._running:
            try:
                stream = self._queue.get(timeout=0.1)
                self._analyze_stream(stream)
            except Empty:
                continue
            except Exception as e:
                logger.error(f"Worker error: {e}")
                self.stats["errors"] += 1
    
    def _get_session(self):
        """Lazy-init HTTP session."""
        if self._session is None:
            try:
                import requests
                self._session = requests.Session()
                self._session.headers.update({
                    "Content-Type": "application/json",
                    "User-Agent": "NGFW-Phase3Bridge/1.0"
                })
            except ImportError:
                logger.error("requests library not available")
                return None
        return self._session
    
    def process(self, stream: ReassembledStream) -> None:
        """
        Process a reassembled stream (callback from TCP Reassembly).
        
        This is the main entry point called by TCPReassembler.
        """
        if not self.config.enabled:
            return
        
        self.stats["streams_received"] += 1
        
        if self.config.log_all_streams:
            logger.info(f"[PHASE3] Received stream {stream.stream_id}: {len(stream.data)} bytes")
        
        # Async mode: queue for processing
        if self.config.async_mode:
            try:
                self._queue.put_nowait(stream)
            except:
                logger.warning("Phase3 queue full, dropping stream")
                self.stats["errors"] += 1
        else:
            # Sync mode: process immediately
            self._analyze_stream(stream)
    
    def _analyze_stream(self, stream: ReassembledStream) -> List[AnalysisResult]:
        """
        Analyze a stream through appropriate Phase-3 modules.
        """
        results = []
        
        try:
            # Detect content type
            content_type = ContentDetector.detect(stream.data, stream.app_protocol)
            
            # Route to appropriate analyzer
            if content_type == 'http_request':
                results.extend(self._analyze_http(stream))
            elif content_type == 'http_response':
                results.extend(self._analyze_http_response(stream))
            elif content_type == 'file_download':
                results.extend(self._analyze_file(stream))
            elif content_type in ('dns_query', 'possible_dns'):
                if self.config.dns_security:
                    results.extend(self._analyze_dns(stream))
            else:
                # Generic content analysis
                if self.config.content_filtering:
                    results.extend(self._analyze_content(stream))
            
            self.stats["streams_analyzed"] += 1
            
            # Log any threats
            threats = [r for r in results if r.verdict == "block"]
            if threats:
                self.stats["threats_detected"] += len(threats)
                for threat in threats:
                    logger.warning(
                        f"[PHASE3 THREAT] {threat.analyzer}: {threat.reason} | "
                        f"Stream: {stream.stream_id} | Confidence: {threat.confidence}%"
                    )
            
        except Exception as e:
            logger.error(f"Stream analysis error: {e}")
            self.stats["errors"] += 1
        
        return results
    
    def _analyze_http(self, stream: ReassembledStream) -> List[AnalysisResult]:
        """Analyze HTTP request for URLs and threats."""
        results = []
        
        if not self.config.url_filtering:
            return results
        
        self.stats["http_requests_analyzed"] += 1
        
        # Extract URLs
        urls = ContentDetector.extract_urls_from_http(stream.data)
        
        for url in urls[:5]:  # Limit to 5 URLs per stream
            result = self._call_api("/api/url/analyze", {"url": url})
            if result:
                self.stats["urls_analyzed"] += 1
                
                is_blocked = result.get("blocked", False) or result.get("is_blocked", False)
                verdict = "block" if is_blocked else "allow"
                
                results.append(AnalysisResult(
                    stream_id=stream.stream_id,
                    analyzer="url_filter",
                    verdict=verdict,
                    confidence=result.get("confidence", 0),
                    reason=result.get("reason", result.get("category", "")),
                    details={"url": url, "result": result}
                ))
        
        return results
    
    def _analyze_http_response(self, stream: ReassembledStream) -> List[AnalysisResult]:
        """Analyze HTTP response for file downloads and content."""
        results = []
        
        # Check for file download in response body
        # Look for Content-Type and body
        data = stream.data
        
        # Simple check: if body contains PE header after headers
        header_end = data.find(b'\r\n\r\n')
        if header_end > 0:
            body = data[header_end + 4:]
            if body.startswith(b'MZ') and self.config.malware_detection:
                # PE file detected in response
                results.extend(self._analyze_pe_data(stream.stream_id, body))
        
        return results
    
    def _analyze_file(self, stream: ReassembledStream) -> List[AnalysisResult]:
        """Analyze file download for malware."""
        results = []
        
        if not self.config.malware_detection:
            return results
        
        self.stats["files_analyzed"] += 1
        
        # Only analyze PE files for now
        if stream.data.startswith(b'MZ'):
            results.extend(self._analyze_pe_data(stream.stream_id, stream.data))
        
        return results
    
    def _analyze_pe_data(self, stream_id: str, pe_data: bytes) -> List[AnalysisResult]:
        """Send PE file to malware detection endpoint."""
        results = []
        
        try:
            # Use the dedicated stream analysis endpoint if available
            # Otherwise fall back to file upload
            result = self._call_api_stream_analysis(stream_id, pe_data, "file")
            
            if result:
                is_malicious = result.get("is_malicious", False)
                verdict = "block" if is_malicious else "allow"
                
                results.append(AnalysisResult(
                    stream_id=stream_id,
                    analyzer="malware_detection",
                    verdict=verdict,
                    confidence=result.get("confidence", 0),
                    reason=result.get("prediction", result.get("message", "")),
                    details=result
                ))
        except Exception as e:
            logger.error(f"PE analysis error: {e}")
            self.stats["errors"] += 1
        
        return results
    
    def _analyze_dns(self, stream: ReassembledStream) -> List[AnalysisResult]:
        """Analyze DNS query for security."""
        results = []
        
        # DNS analysis would require parsing DNS packets
        # For now, log that we detected DNS traffic
        logger.debug(f"[PHASE3] DNS traffic detected in stream {stream.stream_id}")
        
        return results
    
    def _analyze_content(self, stream: ReassembledStream) -> List[AnalysisResult]:
        """Analyze generic content."""
        results = []
        
        if not self.config.content_filtering:
            return results
        
        # Call content analysis API
        result = self._call_api_stream_analysis(
            stream.stream_id, 
            stream.data, 
            "content"
        )
        
        if result:
            is_blocked = result.get("blocked", False)
            verdict = "block" if is_blocked else "allow"
            
            results.append(AnalysisResult(
                stream_id=stream.stream_id,
                analyzer="content_filter",
                verdict=verdict,
                reason=result.get("reason", ""),
                details=result
            ))
        
        return results
    
    def _call_api(self, endpoint: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Make HTTP API call to Phase-3 backend."""
        session = self._get_session()
        if not session:
            return None
        
        url = f"{self.config.api_base_url}{endpoint}"
        
        try:
            self.stats["api_calls"] += 1
            response = session.post(url, json=data, timeout=self.config.timeout_seconds)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self.stats["api_failures"] += 1
            logger.debug(f"API call failed: {endpoint} - {e}")
            return None
    
    def _call_api_stream_analysis(
        self, 
        stream_id: str, 
        data: bytes, 
        analysis_type: str
    ) -> Optional[Dict[str, Any]]:
        """
        Call dedicated stream analysis endpoint.
        Falls back to individual endpoints if stream endpoint unavailable.
        """
        # Try dedicated stream endpoint first
        payload = {
            "stream_id": stream_id,
            "data_b64": base64.b64encode(data).decode('utf-8'),
            "analysis_type": analysis_type
        }
        
        result = self._call_api("/api/stream/analyze", payload)
        if result:
            return result
        
        # Fallback: use individual endpoints based on type
        if analysis_type == "file" and data.startswith(b'MZ'):
            # For file analysis, we'd need multipart upload
            # Skip for now as it requires different handling
            pass
        
        return None
    
    def get_stats(self) -> Dict[str, Any]:
        """Get bridge statistics."""
        return {
            **self.stats,
            "queue_size": self._queue.qsize() if self._queue else 0,
            "enabled": self.config.enabled,
            "async_mode": self.config.async_mode
        }
    
    def shutdown(self):
        """Clean shutdown."""
        logger.info("Phase3Bridge shutting down...")
        self._stop_workers()
        if self._session:
            self._session.close()


# Convenience function for creating bridge with config file
def create_bridge_from_config(config_path: str = "config/phase3_config.json") -> Phase3Bridge:
    """Create Phase3Bridge from configuration file."""
    config = Phase3Config()
    
    try:
        from pathlib import Path
        path = Path(config_path)
        if path.exists():
            with open(path) as f:
                cfg = json.load(f)
            
            p3_cfg = cfg.get("phase3_integration", {})
            config.enabled = p3_cfg.get("enabled", True)
            config.api_base_url = p3_cfg.get("api_base_url", config.api_base_url)
            config.timeout_seconds = p3_cfg.get("timeout_seconds", config.timeout_seconds)
            config.async_mode = p3_cfg.get("async_processing", config.async_mode)
            config.batch_size = p3_cfg.get("batch_size", config.batch_size)
            
            analyzers = p3_cfg.get("analyzers", {})
            config.malware_detection = analyzers.get("malware", True)
            config.url_filtering = analyzers.get("url_filter", True)
            config.content_filtering = analyzers.get("content_filter", True)
            config.dns_security = analyzers.get("dns_security", True)
            config.antibot = analyzers.get("antibot", True)
            config.sandboxing = analyzers.get("sandboxing", False)
            
            logger.info(f"Loaded Phase3 config from {config_path}")
    except Exception as e:
        logger.warning(f"Could not load Phase3 config: {e}, using defaults")
    
    return Phase3Bridge(config=config)


# Default instance for easy import
_default_bridge: Optional[Phase3Bridge] = None

def get_bridge() -> Phase3Bridge:
    """Get or create default Phase3Bridge instance."""
    global _default_bridge
    if _default_bridge is None:
        _default_bridge = create_bridge_from_config()
    return _default_bridge












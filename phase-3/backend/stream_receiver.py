"""
Stream Receiver for Phase-3 Security Backend

Receives reassembled TCP streams from NGFW pipeline and routes
to appropriate security analyzers.
"""
import base64
import logging
import time
from typing import Dict, Any, Optional, List
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class StreamAnalysisRequest(BaseModel):
    """Request model for stream analysis."""
    stream_id: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    data_b64: str  # Base64-encoded stream data
    direction: Optional[str] = None  # "c2s" or "s2c"
    app_protocol: Optional[str] = None
    analysis_type: Optional[str] = None  # "file", "url", "content", "dns"
    dpi_verdict: Optional[Dict[str, Any]] = None


class StreamAnalysisResult(BaseModel):
    """Result from stream analysis."""
    stream_id: str
    verdict: str  # "allow", "block", "warn"
    analyses: List[Dict[str, Any]]
    total_threats: int = 0
    processing_time_ms: float = 0.0


def register_stream_endpoints(app):
    """
    Register stream analysis endpoints with FastAPI app.
    
    Call this from main.py to add stream receiver capability.
    """
    from fastapi import HTTPException
    
    @app.post("/api/stream/analyze", response_model=StreamAnalysisResult)
    async def analyze_stream(request: StreamAnalysisRequest):
        """
        Analyze a reassembled TCP stream.
        
        This is the main endpoint for receiving streams from the NGFW pipeline.
        Routes to appropriate analyzers based on content type.
        """
        start_time = time.time()
        
        try:
            # Decode stream data
            data = base64.b64decode(request.data_b64)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid base64 data: {e}")
        
        if not data:
            raise HTTPException(status_code=400, detail="Empty stream data")
        
        results = {
            "stream_id": request.stream_id,
            "verdict": "allow",
            "analyses": [],
            "total_threats": 0
        }
        
        # Route based on analysis type or auto-detect
        analysis_type = request.analysis_type or detect_content_type(data, request.app_protocol)
        
        try:
            if analysis_type == "file" or is_pe_file(data):
                # Malware detection
                result = await analyze_malware(data, request.stream_id)
                results["analyses"].append({"type": "malware", "result": result})
                if result.get("is_malicious"):
                    results["total_threats"] += 1
                    results["verdict"] = "block"
                    # Add severity for DB/UI
                    for analysis in results["analyses"]:
                        if analysis["type"] == "malware":
                            analysis["severity"] = "Critical"
            
            if analysis_type == "url" or request.app_protocol in ("HTTP", "HTTPS"):
                # URL extraction and analysis
                urls = extract_urls(data)
                for url in urls[:5]:  # Limit
                    result = await analyze_url_security(url)
                    results["analyses"].append({"type": "url", "url": url, "result": result})
                    if result.get("blocked"):
                        results["total_threats"] += 1
                        results["verdict"] = "block"
            
            if analysis_type == "content" or analysis_type is None:
                # Content filtering
                result = await analyze_content_security(data, f"stream_{request.stream_id}")
                results["analyses"].append({"type": "content", "result": result})
                if result.get("blocked"):
                    results["total_threats"] += 1
                    results["verdict"] = "block"
            
        except Exception as e:
            logger.error(f"Stream analysis error: {e}")
            results["analyses"].append({"type": "error", "error": str(e)})
        
        # Calculate processing time
        results["processing_time_ms"] = (time.time() - start_time) * 1000
        
        # Log threats
        if results["total_threats"] > 0:
            logger.warning(
                f"[STREAM THREAT] Stream {request.stream_id}: "
                f"{results['total_threats']} threats detected, verdict={results['verdict']}"
            )
        
        # Save to database
        try:
            from . import database as db
            db.log_stream_analysis(
                stream_id=request.stream_id,
                src_ip=request.src_ip,
                dst_ip=request.dst_ip,
                src_port=request.src_port,
                dst_port=request.dst_port,
                data_size=len(data),
                verdict=results["verdict"],
                threats_found=results["total_threats"],
                analyses=results["analyses"]
            )
        except Exception as e:
            logger.error(f"Failed to log stream analysis: {e}")
        
        return StreamAnalysisResult(**results)
    
    @app.get("/api/stream/stats")
    async def stream_analysis_stats():
        """Get stream analysis statistics."""
        try:
            from . import database as db
            return db.get_stream_analysis_stats()
        except:
            return {"error": "Stats not available"}
    
    logger.info("Stream receiver endpoints registered")


def detect_content_type(data: bytes, app_protocol: Optional[str] = None) -> str:
    """Detect content type from stream data."""
    if not data:
        return "unknown"
    
    # Check app protocol hint
    if app_protocol:
        proto = app_protocol.lower()
        if proto in ("http", "http/1.1", "http/2"):
            return "url"
        if proto == "dns":
            return "dns"
    
    # Check for PE file
    if data[:2] == b'MZ':
        return "file"
    
    # Check for HTTP
    if data[:4] in (b'GET ', b'POST', b'PUT ', b'HEAD'):
        return "url"
    if data[:5] == b'HTTP/':
        return "url"
    
    return "content"


def is_pe_file(data: bytes) -> bool:
    """Check if data is a PE (Windows executable) file."""
    if len(data) < 64:
        return False
    if data[:2] != b'MZ':
        return False
    # Check PE signature offset
    try:
        pe_offset = int.from_bytes(data[60:64], 'little')
        if pe_offset + 4 <= len(data):
            return data[pe_offset:pe_offset+4] == b'PE\x00\x00'
    except:
        pass
    return False


def extract_urls(data: bytes) -> List[str]:
    """Extract URLs from stream data."""
    import re
    urls = []
    try:
        text = data.decode('utf-8', errors='ignore')
        
        # HTTP request line
        match = re.search(r'^(GET|POST|PUT|DELETE|HEAD)\s+(\S+)\s+HTTP', text, re.MULTILINE)
        if match:
            path = match.group(2)
            host_match = re.search(r'Host:\s*(\S+)', text, re.IGNORECASE)
            if host_match:
                host = host_match.group(1)
                urls.append(f"http://{host}{path}")
        
        # URLs in content
        url_pattern = r'https?://[^\s<>"\']+' 
        urls.extend(re.findall(url_pattern, text))
        
    except Exception as e:
        logger.debug(f"URL extraction error: {e}")
    
    return list(set(urls))


async def analyze_malware(data: bytes, stream_id: str) -> Dict[str, Any]:
    """Analyze file for malware using ML model."""
    try:
        from .feature_extractor import extract_features_from_bytes, FEATURE_COLUMNS
        import pickle
        from pathlib import Path
        import pandas as pd
        
        # Extract features
        features = extract_features_from_bytes(data)
        if features is None:
            return {"error": "Failed to extract features", "is_malicious": False}
        
        # Load model
        model_path = Path(__file__).parent.parent / "ransomware_rf_model_new.pkl"
        if not model_path.exists():
            return {"error": "Model not found", "is_malicious": False}
        
        with open(model_path, "rb") as f:
            model = pickle.load(f)
        
        # Make prediction
        feature_vector = [features.get(col, 0) for col in FEATURE_COLUMNS]
        df = pd.DataFrame([feature_vector], columns=FEATURE_COLUMNS)
        
        prediction = model.predict(df)[0]
        confidence = float(max(model.predict_proba(df)[0])) if hasattr(model, 'predict_proba') else 0.0
        
        is_malicious = prediction == 0
        
        return {
            "is_malicious": is_malicious,
            "prediction": "Ransomware/Malware" if is_malicious else "Legitimate",
            "confidence": round(confidence * 100, 2),
            "stream_id": stream_id
        }
        
    except Exception as e:
        logger.error(f"Malware analysis error: {e}")
        return {"error": str(e), "is_malicious": False}


async def analyze_url_security(url: str) -> Dict[str, Any]:
    """Analyze URL for security threats."""
    try:
        from .url_filter import analyze_url
        return analyze_url(url)
    except Exception as e:
        logger.error(f"URL analysis error: {e}")
        return {"url": url, "blocked": False, "error": str(e)}


async def analyze_content_security(data: bytes, filename: str) -> Dict[str, Any]:
    """Analyze content for security threats."""
    try:
        from .content_filter import analyze_content
        return analyze_content(data, filename)
    except Exception as e:
        logger.error(f"Content analysis error: {e}")
        return {"filename": filename, "blocked": False, "error": str(e)}

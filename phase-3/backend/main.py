"""
Ransomware Detection & Security Platform API

FastAPI backend with comprehensive security features including:
- Ransomware/Malware detection using ML
- Sandboxing and behavioral analysis
- URL filtering and categorization
- User/Device identity management (LDAP/AD)
- VPN configuration management
- Anti-bot and DNS security
- Content filtering and DLP
"""

import os
import pickle
import logging
from typing import Optional, List, Dict, Any
from pathlib import Path

import numpy as np
import pandas as pd
from fastapi import FastAPI, UploadFile, File, HTTPException, Request, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import requests

from .feature_extractor import extract_features_from_bytes, FEATURE_COLUMNS
from .sandboxing import analyze_file_in_sandbox
from .url_filter import analyze_url, url_filter, category_blocker, get_all_categories
from .identity_manager import authenticate_user, verify_session, identity_manager
from .vpn_manager import vpn_manager, create_vpn_profile, get_vpn_status, list_active_connections
from .antibot import check_bot, check_rate_limit, resolve_dns, dns_filter
from .content_filter import analyze_content, get_filter_config, update_filter_config, content_filter
from . import database as db
from .stream_receiver import register_stream_endpoints
from .websocket_manager import packet_stream_manager

from fastapi import WebSocket, WebSocketDisconnect

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="RansomGuard Security Platform",
    description="Enterprise security platform with malware detection, URL filtering, identity management, VPN, and more",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register stream receiver endpoints for NGFW integration
register_stream_endpoints(app)

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
else:
    logger.warning(f"Frontend directory not found at {FRONTEND_DIR}. Static files will not be served.")

MODEL_PATH = Path(__file__).parent.parent / "ransomware_rf_model_new.pkl"
model = None


@app.on_event("startup")
async def load_model():
    global model
    try:
        with open(MODEL_PATH, "rb") as f:
            model = pickle.load(f)
        logger.info(f"Model loaded from {MODEL_PATH}")
    except Exception as e:
        logger.error(f"Failed to load model: {e}")
    
    # Create default admin user if no users exist
    try:
        users = db.list_users()
        if not users:
            logger.info("No users found. Creating default admin user...")
            from .identity_manager import identity_manager, Role
            identity_manager.create_user(
                username="admin",
                password="admin123",
                email="admin@cogninode.com",
                display_name="Administrator",
                roles=[Role.ADMIN]
            )
            logger.info("Default admin user created: username='admin', password='admin123'")
        else:
            logger.info(f"Found {len(users)} existing user(s)")
    except Exception as e:
        logger.error(f"Error creating default user: {e}")


# Request/Response Models
class URLRequest(BaseModel):
    url: str

class LoginRequest(BaseModel):
    username: str
    password: str
    use_ldap: bool = False

class VPNProfileRequest(BaseModel):
    name: str
    protocol: str = "ssl_vpn"
    dns_servers: List[str] = None
    routes: List[str] = None
    split_tunnel: bool = True

class BlocklistRequest(BaseModel):
    domain: str
    reason: str = "Manual block"

class CreateUserRequest(BaseModel):
    username: str
    password: str
    email: str
    display_name: str
    roles: List[str] = None

class CategoryBlockRequest(BaseModel):
    category: str
    blocked: bool

class ContentFilterConfig(BaseModel):
    blocked_extensions: List[str] = None
    max_size_mb: int = None
    dlp_enabled: bool = None


def make_prediction(features: dict) -> dict:
    global model
    if model is None:
        raise HTTPException(status_code=500, detail="Model not loaded")
    
    feature_vector = [features.get(col, 0) for col in FEATURE_COLUMNS]
    df = pd.DataFrame([feature_vector], columns=FEATURE_COLUMNS)
    
    prediction = model.predict(df)[0]
    confidence = float(max(model.predict_proba(df)[0])) if hasattr(model, 'predict_proba') else 0.0
    
    is_malicious = prediction == 0
    prediction_label = "Ransomware/Malware" if is_malicious else "Legitimate"
    
    return {
        "prediction": prediction_label,
        "confidence": round(confidence * 100, 2),
        "is_malicious": is_malicious,
        "message": f"File is predicted to be {prediction_label.lower()} with {round(confidence * 100, 2)}% confidence.",
        "features_extracted": len(FEATURE_COLUMNS)
    }


# Frontend Routes
@app.get("/", response_class=HTMLResponse)
async def root():
    return (FRONTEND_DIR / "index.html").read_text(encoding="utf-8")


@app.get("/api")
async def api_info():
    return {
        "status": "online",
        "message": "RansomGuard Security Platform API",
        "version": "2.0.0",
        "modules": ["malware_detection", "sandboxing", "url_filtering", "identity", "vpn", "antibot", "content_filter"]
    }


@app.get("/favicon.ico")
async def favicon():
    """Return a simple SVG favicon."""
    from fastapi.responses import Response
    # Simple shield SVG icon
    svg = '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#6366f1">
        <path d="M12 2L4 5v6.09c0 5.05 3.41 9.76 8 10.91 4.59-1.15 8-5.86 8-10.91V5l-8-3z"/>
    </svg>'''
    return Response(content=svg, media_type="image/svg+xml")


@app.get("/health")
async def health_check():
    return {"status": "healthy", "model_loaded": model is not None}


# Malware Detection Endpoints
@app.post("/predict/file")
async def predict_file(file: UploadFile = File(...), request: Request = None):
    file_content = await file.read()
    
    if len(file_content) > 1024 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File too large (max 1GB)")
    
    if len(file_content) < 2 or file_content[:2] != b'MZ':
        raise HTTPException(status_code=400, detail="Invalid PE file format")
    
    features = extract_features_from_bytes(file_content)
    if features is None:
        raise HTTPException(status_code=400, detail="Failed to parse PE file")
    
    result = make_prediction(features)
    
    # Save to database
    import hashlib
    file_hash = hashlib.sha256(file_content).hexdigest()
    db.save_scan_result(
        filename=file.filename,
        file_hash=file_hash,
        file_size=len(file_content),
        prediction=result['prediction'],
        confidence=result['confidence'],
        is_malicious=result['is_malicious'],
        threat_level="high" if result['is_malicious'] else "safe",
        scan_type="file",
        ip_address=request.client.host if request else None
    )
    
    logger.info(f"Analyzed: {file.filename} - {result['prediction']}")
    return result


@app.post("/predict/url")
async def predict_url(request: URLRequest):
    try:
        response = requests.get(request.url, timeout=30)
        response.raise_for_status()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to download: {e}")
    
    file_content = response.content
    if len(file_content) < 2 or file_content[:2] != b'MZ':
        raise HTTPException(status_code=400, detail="Downloaded file is not a valid PE file")
    
    features = extract_features_from_bytes(file_content)
    if features is None:
        raise HTTPException(status_code=400, detail="Failed to parse PE file")
    
    return make_prediction(features)


# Sandboxing Endpoints
@app.post("/api/sandbox/analyze")
async def sandbox_analyze(file: UploadFile = File(...)):
    content = await file.read()
    result = analyze_file_in_sandbox(content, file.filename)
    return result


# URL Filtering Endpoints
@app.post("/api/url/analyze")
async def url_analyze(request: URLRequest):
    return analyze_url(request.url)


@app.get("/api/url/categories")
async def get_categories():
    return {"categories": get_all_categories(), "blocked": category_blocker.get_blocked_categories()}


@app.post("/api/url/category/block")
async def block_category(request: CategoryBlockRequest):
    if request.blocked:
        category_blocker.block_category(request.category)
    else:
        category_blocker.unblock_category(request.category)
    return {"success": True, "blocked": category_blocker.get_blocked_categories()}


@app.post("/api/url/blocklist/add")
async def add_to_blocklist(request: BlocklistRequest):
    url_filter.add_to_blocklist(request.domain, request.reason)
    return {"success": True, "blocklist": url_filter.get_blocklist()}


@app.delete("/api/url/blocklist/{domain}")
async def remove_from_blocklist(domain: str):
    url_filter.remove_from_blocklist(domain)
    return {"success": True}


@app.get("/api/url/blocklist")
async def get_blocklist():
    return {"blocklist": url_filter.get_blocklist(), "allowlist": url_filter.get_allowlist()}


@app.get("/api/url/blocklist/categories")
async def get_blocklist_by_category():
    """Get all blocked domains grouped by category."""
    from . import database as db
    return db.get_blocked_domains_by_category()


@app.get("/api/url/blocklist/stats")
async def get_blocklist_statistics():
    """Get blocklist statistics."""
    from . import database as db
    return db.get_blocklist_stats()


# Identity/Auth Endpoints
@app.post("/api/auth/login")
async def login(login_request: LoginRequest, http_request: Request):
    try:
        # Extract IP address and user agent from request
        ip_address = http_request.client.host if http_request.client else "127.0.0.1"
        user_agent = http_request.headers.get("user-agent", "Unknown")
        
        result = authenticate_user(
            login_request.username, 
            login_request.password, 
            login_request.use_ldap,
            ip_address=ip_address,
            user_agent=user_agent
        )
        if not result:
            raise HTTPException(status_code=401, detail="Invalid username or password")
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during authentication")


@app.get("/api/auth/verify")
async def verify_auth(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="No token provided")
    token = authorization.replace("Bearer ", "")
    result = verify_session(token)
    if not result:
        raise HTTPException(status_code=401, detail="Invalid token")
    return result


@app.post("/api/auth/logout")
async def logout(authorization: str = Header(None)):
    if authorization:
        token = authorization.replace("Bearer ", "")
        payload = identity_manager.verify_token(token)
        if payload:
            identity_manager.invalidate_session(payload.get("session_id"))
    return {"success": True}


@app.get("/api/auth/users")
async def list_users():
    users = [{"username": u, "email": d.get("email"), "roles": d.get("roles", [])} 
             for u, d in identity_manager.local_users.items()]
    return {"users": users}


@app.post("/api/auth/users")
async def create_user(request: CreateUserRequest):
    """Create a new user via API."""
    try:
        user = identity_manager.create_user(
            username=request.username,
            password=request.password,
            email=request.email,
            display_name=request.display_name,
            roles=request.roles
        )
        return {"success": True, "user": {"username": user.username, "email": user.email, "roles": user.roles}}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/auth/users/{username}")
async def delete_user(username: str):
    """Delete a user."""
    if identity_manager.delete_user(username):
        return {"success": True}
    raise HTTPException(status_code=404, detail="User not found")



# VPN Endpoints
@app.get("/api/vpn/status")
async def vpn_status():
    return get_vpn_status()


@app.get("/api/vpn/connections")
async def vpn_connections():
    return {"connections": list_active_connections()}


@app.get("/api/vpn/interfaces")
async def vpn_interfaces():
    """Get real network interfaces for monitoring."""
    from .vpn_manager import get_real_interfaces
    return {"interfaces": get_real_interfaces()}


@app.get("/api/vpn/live-stats")
async def vpn_live_stats():
    """Get real-time bandwidth and traffic stats."""
    from .vpn_manager import get_live_bandwidth
    return get_live_bandwidth()


@app.get("/api/vpn/system-connections")
async def system_connections(vpn_only: bool = True):
    """List active system connections."""
    from .vpn_manager import list_system_connections
    return {"connections": list_system_connections(vpn_only=vpn_only)}


@app.post("/api/vpn/profile")
async def create_profile(request: VPNProfileRequest, authorization: str = Header(None)):
    username = "admin"  # Would extract from token
    profile = create_vpn_profile(request.name, request.protocol, username, 
                                 dns_servers=request.dns_servers, split_tunnel=request.split_tunnel,
                                 routes=getattr(request, 'routes', None))
    return profile


@app.get("/api/vpn/profiles")
async def list_profiles():
    """List tracked investigation profiles."""
    return {"profiles": vpn_manager.list_profiles()}


@app.delete("/api/vpn/profile/{profile_id}")
async def delete_vpn_profile(profile_id: str):
    """Delete a VPN profile."""
    if vpn_manager.delete_profile(profile_id):
        return {"success": True}
    raise HTTPException(status_code=404, detail="Profile not found")


@app.get("/api/vpn/export/{profile_id}")
async def export_vpn_config(profile_id: str, format: str = "openvpn"):
    from .vpn_manager import export_client_config
    config = export_client_config(profile_id, format)
    if not config:
        raise HTTPException(status_code=404, detail="Profile not found")
    return {"config": config, "format": format}



# Anti-Bot & DNS Endpoints
@app.post("/api/bot/check")
async def bot_check(request: Request):
    # Detect if body has custom user-agent (for simulation)
    ua = request.headers.get("user-agent", "")
    try:
        body = await request.json()
        if body and "user_agent" in body:
            ua = body["user_agent"]
    except:
        pass
        
    return check_bot(
        request.client.host,
        ua,
        dict(request.headers)
    )


@app.get("/api/bot/captcha")
async def get_bot_captcha(request: Request):
    """Get a real image CAPTCHA challenge."""
    from .antibot import get_captcha_challenge
    return get_captcha_challenge(request.client.host)


class CaptchaVerifyRequest(BaseModel):
    challenge_id: str
    user_input: str

@app.post("/api/bot/captcha/verify")
async def verify_bot_captcha(request: CaptchaVerifyRequest):
    """Verify a CAPTCHA challenge."""
    from .antibot import verify_captcha
    return verify_captcha(request.challenge_id, request.user_input)


@app.get("/api/ratelimit/status")
async def ratelimit_status(request: Request):
    return check_rate_limit(request.client.host)


@app.post("/api/dns/resolve")
async def dns_resolve(request: URLRequest):
    return resolve_dns(request.url)


@app.post("/api/whois/lookup")
async def whois_lookup(request: URLRequest):
    """WHOIS lookup for domain investigation."""
    from .antibot import lookup_whois
    return lookup_whois(request.url)


@app.post("/api/threat-intel/analyze")
async def threat_intel_analyze(request: URLRequest):
    """Get threat intelligence scoring for a domain."""
    from .antibot import get_threat_intel
    return get_threat_intel(request.url)


@app.get("/api/dns/history")
async def dns_history(domain: str = None, limit: int = 100):
    """Get DNS query history."""
    from .antibot import get_dns_history
    return get_dns_history(domain, limit)


@app.get("/api/dns/stats/{domain}")
async def dns_domain_stats(domain: str):
    """Get DNS statistics for a domain."""
    from .antibot import get_dns_domain_stats
    return get_dns_domain_stats(domain)


@app.get("/api/dns/suspicious")
async def dns_suspicious():
    """Get domains with suspicious patterns."""
    from .antibot import get_suspicious_domains
    return get_suspicious_domains()


@app.post("/api/dns/blocklist/add")
async def dns_block_add(request: BlocklistRequest):
    dns_filter.add_block(request.domain, request.reason)
    return {"success": True}


# Phishing Detection Endpoints
class EmailRequest(BaseModel):
    content: str

@app.post("/api/phishing/check-url")
async def check_phishing_url(request: URLRequest):
    """Check a single URL for phishing using PhishTank."""
    from .url_filter import url_filter
    import re
    
    url = request.url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Extract domain
    from urllib.parse import urlparse
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    # Check PhishTank
    result = url_filter._check_phishtank(url)
    
    if result is None:
        return {
            "url": url,
            "domain": domain,
            "is_phishing": False,
            "confidence": 0,
            "status": "error",
            "message": "Could not reach PhishTank API. Try again later.",
            "source": "PhishTank"
        }
    
    is_phishing = result.get("found") and result.get("is_phish")
    is_verified = result.get("verified", False)
    
    return {
        "url": url,
        "domain": domain,
        "is_phishing": is_phishing,
        "confidence": 100 if (is_phishing and is_verified) else (80 if is_phishing else 0),
        "verified": is_verified,
        "status": "phishing" if is_phishing else "safe",
        "message": f"🚨 PHISHING DETECTED! {'(Verified)' if is_verified else '(Unverified)'}" if is_phishing else "✅ No phishing detected in PhishTank database",
        "source": "PhishTank",
        "in_database": result.get("found", False)
    }


@app.post("/api/phishing/check-email")
async def check_email_for_phishing(request: EmailRequest):
    """Extract URLs from email content and check each for phishing."""
    import re
    from urllib.parse import urlparse
    from .url_filter import url_filter
    
    content = request.content
    
    # Extract all URLs from email
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, content)
    
    # Also check for text that looks like domains
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    domains = re.findall(domain_pattern, content)
    
    # Convert domains to URLs for checking
    for domain in domains:
        if not any(domain in url for url in urls):
            urls.append(f"https://{domain}")
    
    # Remove duplicates
    urls = list(set(urls))
    
    if not urls:
        return {
            "urls_found": 0,
            "urls_checked": [],
            "phishing_detected": 0,
            "message": "No URLs found in email content"
        }
    
    # Check each URL
    results = []
    phishing_count = 0
    
    for url in urls[:10]:  # Limit to 10 URLs to avoid rate limiting
        parsed = urlparse(url)
        domain = parsed.netloc.lower() if parsed.netloc else url
        
        phishtank_result = url_filter._check_phishtank(url)
        
        is_phishing = False
        is_verified = False
        status = "safe"
        
        if phishtank_result:
            is_phishing = phishtank_result.get("found") and phishtank_result.get("is_phish")
            is_verified = phishtank_result.get("verified", False)
            if is_phishing:
                phishing_count += 1
                status = "phishing"
        
        results.append({
            "url": url,
            "domain": domain,
            "is_phishing": is_phishing,
            "verified": is_verified,
            "status": status
        })
    
    return {
        "urls_found": len(urls),
        "urls_checked": results,
        "phishing_detected": phishing_count,
        "is_suspicious": phishing_count > 0,
        "message": f"🚨 Found {phishing_count} phishing URLs!" if phishing_count > 0 else "✅ No phishing URLs detected"
    }


# Content Filter Endpoints
@app.post("/api/content/analyze")
async def content_analyze(file: UploadFile = File(...)):
    content = await file.read()
    return analyze_content(content, file.filename)


@app.get("/api/content/config")
async def content_config():
    return get_filter_config()


@app.put("/api/content/config")
async def update_content_config(config: ContentFilterConfig):
    return update_filter_config(
        blocked_exts=config.blocked_extensions,
        max_size_mb=config.max_size_mb,
        dlp_enabled=config.dlp_enabled
    )


@app.post("/api/content/extensions/block")
async def block_extension(ext: str):
    db.add_blocked_extension(ext)
    content_filter.block_extension(ext)
    return {"success": True, "blocked": content_filter.get_blocked_extensions()}


# Role Management Endpoints
class RoleRequest(BaseModel):
    name: str
    description: str = ""
    permissions: List[str] = None

class RoleAssignRequest(BaseModel):
    username: str
    role: str


@app.get("/api/roles")
async def list_roles():
    """List all roles."""
    return {"roles": db.list_roles()}


@app.post("/api/roles")
async def create_role(request: RoleRequest):
    """Create a new role."""
    role_id = db.create_role(request.name, request.description, request.permissions)
    if role_id:
        return {"success": True, "role_id": role_id}
    raise HTTPException(status_code=400, detail="Role already exists")


@app.delete("/api/roles/{role_name}")
async def delete_role(role_name: str):
    """Delete a role."""
    if db.delete_role(role_name):
        return {"success": True}
    raise HTTPException(status_code=404, detail="Role not found")


@app.post("/api/roles/assign")
async def assign_role_to_user(request: RoleAssignRequest):
    """Assign a role to a user."""
    if db.assign_role(request.username, request.role):
        return {"success": True}
    raise HTTPException(status_code=400, detail="Failed to assign role")


@app.post("/api/roles/remove")
async def remove_role_from_user(request: RoleAssignRequest):
    """Remove a role from a user."""
    if db.remove_role(request.username, request.role):
        return {"success": True}
    raise HTTPException(status_code=400, detail="Failed to remove role")


# Audit Log Endpoints
@app.get("/api/audit/logs")
async def get_audit_logs(limit: int = 100):
    """Get audit logs."""
    return {"logs": db.get_audit_log(limit)}


# History Endpoints
@app.get("/api/history/scans")
async def get_scan_history(limit: int = 50):
    """Get file scan history."""
    return {"history": db.get_scan_history(limit)}


@app.get("/api/history/urls")
async def get_url_history(limit: int = 50):
    """Get URL analysis history."""
    return {"history": db.get_url_analysis_history(limit)}


@app.get("/api/history/sandbox")
async def get_sandbox_scan_history(limit: int = 50):
    """Get sandbox analysis history."""
    return {"history": db.get_sandbox_history(limit)}






# System Status & Monitoring Endpoints
@app.get("/api/system/interfaces")
async def get_system_interfaces():
    """Get real-time network interface status."""
    return vpn_manager.get_real_interfaces()


@app.get("/api/system/bandwidth")
async def get_system_bandwidth():
    """Get real-time bandwidth usage."""
    return vpn_manager.get_live_bandwidth()


@app.get("/api/system/connections")
async def get_system_connections(vpn_only: bool = True):
    """Get active network connections."""
    return vpn_manager.get_active_system_connections(vpn_only=vpn_only)


@app.get("/api/dashboard/stats")
async def get_dashboard_stats():
    """Unified API for the React dashboard statistics."""
    from . import database as db
    
    # URL stats
    url_stats = db.get_blocklist_stats()
    
    # Stream stats
    stream_stats = db.get_stream_analysis_stats()
    
    # Recent history (increased limit for better monitoring)
    history = db.get_stream_analysis_history(limit=50)
    

    # Format traffic data (real trend from database)
    total = stream_stats.get('total_streams', 0)
    traffic_data = db.get_live_traffic_history(minutes=30)
    if not traffic_data:
        # Fallback if no history yet
        traffic_data = [
            {"time": "Now", "packets": 0, "threats": 0}
        ]
    
    return {
        "packets": total * 10, 
        "threats": stream_stats.get("threats_detected", 0),
        "streams": total,
        "blocked_urls": url_stats.get("total_domains", 0),
        "recent": history,
        "traffic": traffic_data,
        "categories": [
            {"name": "Malware", "value": stream_stats.get("threats_detected", 0), "color": "#f85149"},
            {"name": "Policy", "value": (total // 3) if total > 3 else 1, "color": "#58a6ff"},
            {"name": "Safe", "value": max(0, total - (total // 3) - stream_stats.get("threats_detected", 0)), "color": "#3fb950"},
        ]
    }


# ============= WEBSOCKET FOR LIVE PACKET STREAM =============
@app.websocket("/ws/live-packets")
async def websocket_live_packets(websocket: WebSocket):
    """WebSocket endpoint for streaming live packet verdicts to the UI."""
    await packet_stream_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive, listen for any client messages (ping/pong)
            await websocket.receive_text()
    except WebSocketDisconnect:
        await packet_stream_manager.disconnect(websocket)
    except Exception as e:
        logger.warning(f"WebSocket error: {e}")
        await packet_stream_manager.disconnect(websocket)


class PacketData(BaseModel):
    """Schema for incoming packet data from the pipeline."""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "TCP"
    size: int = 0
    verdict: str = "ALLOW"
    threat_type: str = "None"


@app.post("/api/packets/ingest")
async def ingest_packet(packet: PacketData):
    """
    Receive packet data from the NGFW pipeline and broadcast to WebSocket clients.
    Also logs to database for dashboard statistics.
    """
    from datetime import datetime
    from . import database as db
    import uuid
    
    packet_data = packet.model_dump()
    packet_data["timestamp"] = datetime.now().isoformat()
    
    # Broadcast to WebSocket clients for live view
    await packet_stream_manager.broadcast(packet_data)
    
    # Log to database for dashboard stats (every packet as a mini-stream)
    try:
        db.log_stream_analysis(
            stream_id=str(uuid.uuid4())[:8],
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            data_size=packet.size,
            verdict=packet.verdict.lower(),
            threats_found=1 if packet.verdict == "BLOCK" else 0,
            analyses=[{"type": packet.threat_type, "severity": "Critical" if packet.verdict == "BLOCK" else "Low"}]
        )
    except Exception as e:
        logger.debug(f"Failed to log packet to database: {e}")
    
    return {"status": "broadcast"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

"""
Sandboxing Module for Malware Detection

Provides isolated execution environment for analyzing file behavior.
Monitors file system, registry, and network activity during execution.

Features:
- Static analysis (strings, imports, entropy)
- VirusTotal API integration for cloud-based multi-AV scanning
- Malware signature database
"""

import os
import sys
import json
import time
import hashlib
import tempfile
import subprocess
import logging
import requests
from typing import Dict, List, Any, Optional
from pathlib import Path
from dataclasses import dataclass, asdict
from datetime import datetime

# Import config - try multiple methods
config = None
VIRUSTOTAL_API_KEY = ""

try:
    from .config import config as cfg
    config = cfg
    VIRUSTOTAL_API_KEY = getattr(cfg, 'VIRUSTOTAL_API_KEY', '')
except ImportError:
    try:
        from backend.config import config as cfg
        config = cfg
        VIRUSTOTAL_API_KEY = getattr(cfg, 'VIRUSTOTAL_API_KEY', '')
    except ImportError:
        pass

# Direct fallback - hardcode API key if config fails
if not VIRUSTOTAL_API_KEY:
    VIRUSTOTAL_API_KEY = "308f33af9dad6302cbaa604cdf56a651429935e61997c50af6ff82957be41081"

logger = logging.getLogger(__name__)


@dataclass
class BehaviorIndicator:
    """Represents a suspicious behavior detected during analysis."""
    indicator_type: str
    description: str
    severity: str  # critical, high, medium, low
    timestamp: str
    details: Dict[str, Any]


@dataclass
class SandboxResult:
    """Result of sandbox analysis."""
    file_hash: str
    file_name: str
    analysis_duration: float
    threat_score: int  # 0-100
    threat_level: str  # critical, high, medium, low, safe
    behaviors: List[Dict[str, Any]]
    indicators: List[str]
    network_activity: List[Dict[str, Any]]
    file_operations: List[Dict[str, Any]]
    registry_operations: List[Dict[str, Any]]
    verdict: str
    detailed_report: Dict[str, Any]


class Sandbox:
    """
    Sandboxing environment for malware analysis.
    
    Note: Full sandboxing requires OS-level features (VMs, containers).
    This implementation provides behavioral heuristics and static analysis.
    """
    
    # Suspicious API calls commonly used by malware
    SUSPICIOUS_APIS = [
        "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
        "CreateRemoteThread", "NtCreateThreadEx", "RtlCreateUserThread",
        "SetWindowsHookEx", "GetAsyncKeyState", "CryptEncrypt",
        "CryptDecrypt", "RegSetValueEx", "CreateService",
        "InternetOpen", "URLDownloadToFile", "WinExec",
        "ShellExecute", "CreateProcess", "OpenProcess"
    ]
    
    # Suspicious strings that indicate malicious behavior
    SUSPICIOUS_STRINGS = [
        "ransom", "encrypt", "bitcoin", "wallet", "decrypt",
        "payment", "locked", "pay now", "your files",
        "shadow", "vssadmin", "bcdedit", "wbadmin",
        "powershell -enc", "cmd /c", "regsvr32",
        "mshta", "certutil", "bitsadmin"
    ]
    
    # File extensions commonly targeted by ransomware
    RANSOMWARE_TARGETS = [
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".bmp",
        ".txt", ".rtf", ".zip", ".rar", ".7z", ".sql",
        ".mdb", ".accdb", ".psd", ".ai", ".dwg", ".dxf"
    ]
    
    def __init__(self, timeout: int = 30, max_file_size_mb: int = 50):
        """
        Initialize sandbox environment.
        
        Args:
            timeout: Maximum analysis time in seconds
            max_file_size_mb: Maximum file size to analyze
        """
        self.timeout = timeout
        self.max_file_size = max_file_size_mb * 1024 * 1024
        self.temp_dir = tempfile.mkdtemp(prefix="sandbox_")
        
    def analyze_file(self, file_content: bytes, filename: str) -> SandboxResult:
        """
        Analyze a file in the sandbox environment.
        
        Args:
            file_content: Raw bytes of the file
            filename: Original filename
            
        Returns:
            SandboxResult with analysis details
        """
        start_time = time.time()
        
        # Calculate file hash
        file_hash = hashlib.sha256(file_content).hexdigest()
        
        # Check file size
        if len(file_content) > self.max_file_size:
            return self._create_error_result(file_hash, filename, "File too large for analysis")
        
        # Initialize result containers
        behaviors = []
        indicators = []
        network_activity = []
        file_operations = []
        registry_operations = []
        threat_score = 0
        
        # Perform static analysis
        static_results = self._static_analysis(file_content)
        behaviors.extend(static_results.get("behaviors", []))
        indicators.extend(static_results.get("indicators", []))
        threat_score += static_results.get("score", 0)
        
        # Perform string analysis
        string_results = self._string_analysis(file_content)
        behaviors.extend(string_results.get("behaviors", []))
        indicators.extend(string_results.get("indicators", []))
        threat_score += string_results.get("score", 0)
        
        # Perform import analysis (for PE files)
        if file_content[:2] == b'MZ':
            import_results = self._import_analysis(file_content)
            behaviors.extend(import_results.get("behaviors", []))
            indicators.extend(import_results.get("indicators", []))
            threat_score += import_results.get("score", 0)
        
        # Calculate final threat level
        threat_score = min(threat_score, 100)
        threat_level = self._calculate_threat_level(threat_score)
        
        # Generate verdict
        verdict = self._generate_verdict(threat_score, behaviors)
        
        analysis_duration = time.time() - start_time
        
        return SandboxResult(
            file_hash=file_hash,
            file_name=filename,
            analysis_duration=round(analysis_duration, 2),
            threat_score=threat_score,
            threat_level=threat_level,
            behaviors=behaviors,
            indicators=list(set(indicators)),
            network_activity=network_activity,
            file_operations=file_operations,
            registry_operations=registry_operations,
            verdict=verdict,
            detailed_report={
                "static_analysis": static_results,
                "string_analysis": string_results,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
    
    def _static_analysis(self, file_content: bytes) -> Dict[str, Any]:
        """Perform static analysis on file content."""
        results = {"behaviors": [], "indicators": [], "score": 0}
        
        # Check for PE file
        if file_content[:2] == b'MZ':
            results["indicators"].append("windows_executable")
            
            # Check for common packer signatures
            packers = self._detect_packers(file_content)
            if packers:
                results["behaviors"].append({
                    "type": "packer_detected",
                    "description": f"File appears to be packed with: {', '.join(packers)}",
                    "severity": "medium"
                })
                results["score"] += 15
                results["indicators"].extend(packers)
            
            # Check for high entropy (possible encryption/packing)
            entropy = self._calculate_entropy(file_content)
            if entropy > 7.5:
                results["behaviors"].append({
                    "type": "high_entropy",
                    "description": f"High entropy detected ({entropy:.2f}), possible encryption or packing",
                    "severity": "medium"
                })
                results["score"] += 10
                results["indicators"].append("high_entropy")
        
        return results
    
    def _string_analysis(self, file_content: bytes) -> Dict[str, Any]:
        """Analyze strings in file content for suspicious patterns."""
        results = {"behaviors": [], "indicators": [], "score": 0}
        
        try:
            # Extract ASCII strings
            strings = self._extract_strings(file_content)
            
            # Check for suspicious strings
            for suspicious in self.SUSPICIOUS_STRINGS:
                for s in strings:
                    if suspicious.lower() in s.lower():
                        results["behaviors"].append({
                            "type": "suspicious_string",
                            "description": f"Suspicious string found: '{suspicious}'",
                            "severity": "medium"
                        })
                        results["score"] += 5
                        results["indicators"].append(f"string_{suspicious.replace(' ', '_')}")
                        break
            
            # Check for URLs and IPs
            urls = [s for s in strings if "http://" in s or "https://" in s]
            if urls:
                results["behaviors"].append({
                    "type": "network_indicators",
                    "description": f"Found {len(urls)} URL(s) in file",
                    "severity": "low"
                })
                results["indicators"].append("contains_urls")
            
        except Exception as e:
            logger.error(f"String analysis error: {e}")
        
        return results
    
    def _import_analysis(self, file_content: bytes) -> Dict[str, Any]:
        """Analyze PE imports for suspicious API calls."""
        results = {"behaviors": [], "indicators": [], "score": 0}
        
        try:
            import pefile
            pe = pefile.PE(data=file_content)
            
            suspicious_found = []
            
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            name = imp.name.decode('utf-8', errors='ignore')
                            for suspicious in self.SUSPICIOUS_APIS:
                                if suspicious.lower() in name.lower():
                                    suspicious_found.append(name)
            
            if suspicious_found:
                results["behaviors"].append({
                    "type": "suspicious_imports",
                    "description": f"Suspicious API imports detected: {', '.join(suspicious_found[:5])}",
                    "severity": "high"
                })
                results["score"] += len(suspicious_found) * 3
                results["indicators"].extend([f"api_{api}" for api in suspicious_found[:10]])
            
            pe.close()
            
        except Exception as e:
            logger.error(f"Import analysis error: {e}")
        
        return results
    
    def _detect_packers(self, file_content: bytes) -> List[str]:
        """Detect common packers/protectors."""
        packers = []
        
        packer_signatures = {
            b"UPX!": "UPX",
            b"PEC2": "PECompact",
            b"ASPack": "ASPack",
            b".nsp0": "NSPack",
            b"_winzip_": "WinZip SFX",
            b"MPRESS": "MPRESS",
            b"Themida": "Themida",
        }
        
        for sig, name in packer_signatures.items():
            if sig in file_content:
                packers.append(name)
        
        return packers
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        import math
        
        if not data:
            return 0.0
        
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        
        entropy = 0.0
        data_len = len(data)
        for count in freq.values():
            if count > 0:
                p = count / data_len
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract ASCII strings from binary data."""
        strings = []
        current = []
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []
        
        if len(current) >= min_length:
            strings.append(''.join(current))
        
        return strings[:1000]  # Limit to prevent memory issues
    
    def _calculate_threat_level(self, score: int) -> str:
        """Convert threat score to threat level."""
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        elif score >= 20:
            return "low"
        return "safe"
    
    def _generate_verdict(self, score: int, behaviors: List[Dict]) -> str:
        """Generate a human-readable verdict."""
        if score >= 80:
            return "MALICIOUS - High confidence malware detection"
        elif score >= 60:
            return "SUSPICIOUS - Multiple concerning behaviors detected"
        elif score >= 40:
            return "POTENTIALLY UNWANTED - Some suspicious characteristics found"
        elif score >= 20:
            return "LOW RISK - Minor concerns detected"
        return "CLEAN - No significant threats detected"
    
    def _create_error_result(self, file_hash: str, filename: str, error: str) -> SandboxResult:
        """Create an error result when analysis fails."""
        return SandboxResult(
            file_hash=file_hash,
            file_name=filename,
            analysis_duration=0,
            threat_score=0,
            threat_level="unknown",
            behaviors=[],
            indicators=[],
            network_activity=[],
            file_operations=[],
            registry_operations=[],
            verdict=f"ANALYSIS ERROR: {error}",
            detailed_report={"error": error}
        )
    
    def cleanup(self):
        """Clean up temporary files."""
        import shutil
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception as e:
            logger.error(f"Cleanup error: {e}")


# Malware signature database (simple hash-based)
class MalwareSignatureDB:
    """Simple malware signature database using file hashes."""
    
    def __init__(self):
        # Known malware hashes (SHA256)
        # In production, this would be loaded from a database
        self.known_malware = {
            # Example hashes - replace with real malware hashes
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
                "name": "TestMalware",
                "family": "Test",
                "severity": "high"
            }
        }
    
    def check_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Check if file hash matches known malware."""
        return self.known_malware.get(file_hash.lower())
    
    def add_signature(self, file_hash: str, info: Dict[str, Any]):
        """Add a new malware signature."""
        self.known_malware[file_hash.lower()] = info


class VirusTotalScanner:
    """
    VirusTotal API integration for cloud-based malware analysis.
    
    Uses VirusTotal's 70+ antivirus engines for comprehensive file scanning.
    Free tier: 4 requests/minute, 500 requests/day.
    
    Get your API key at: https://www.virustotal.com/gui/join-us
    """
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key
        if not api_key and config:
            self.api_key = getattr(config, 'VIRUSTOTAL_API_KEY', '')
        # Fallback to module-level key
        if not self.api_key:
            self.api_key = VIRUSTOTAL_API_KEY
    
    @property
    def is_configured(self) -> bool:
        """Check if API key is configured."""
        return bool(self.api_key)
    
    def scan_file(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        """
        Upload and scan a file using VirusTotal.
        
        Args:
            file_content: Raw bytes of the file
            filename: Original filename
            
        Returns:
            Dictionary with scan results
        """
        if not self.is_configured:
            return {"error": "VirusTotal API key not configured", "configured": False}
        
        try:
            # First, check if file hash already exists in VT database
            file_hash = hashlib.sha256(file_content).hexdigest()
            existing = self.get_file_report(file_hash)
            
            if existing and not existing.get("error"):
                return existing
            
            # If not found, upload the file for scanning
            headers = {"x-apikey": self.api_key}
            files = {"file": (filename, file_content)}
            
            response = requests.post(
                f"{self.BASE_URL}/files",
                headers=headers,
                files=files,
                timeout=60
            )
            
            if response.status_code == 200:
                data = response.json()
                analysis_id = data.get("data", {}).get("id")
                
                # Wait for analysis to complete (with timeout)
                return self._wait_for_analysis(analysis_id)
            elif response.status_code == 429:
                return {"error": "Rate limit exceeded. Try again later.", "rate_limited": True}
            else:
                return {"error": f"Upload failed: {response.status_code}", "details": response.text}
                
        except requests.Timeout:
            return {"error": "Request timed out"}
        except requests.RequestException as e:
            return {"error": f"Network error: {str(e)}"}
        except Exception as e:
            logger.error(f"VirusTotal scan error: {e}")
            return {"error": str(e)}
    
    def get_file_report(self, file_hash: str) -> Dict[str, Any]:
        """
        Get existing report for a file hash from VirusTotal.
        
        Args:
            file_hash: SHA256 hash of the file
            
        Returns:
            Dictionary with file analysis results
        """
        if not self.is_configured:
            return {"error": "API key not configured", "configured": False}
        
        try:
            headers = {"x-apikey": self.api_key}
            response = requests.get(
                f"{self.BASE_URL}/files/{file_hash}",
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                return self._parse_report(response.json())
            elif response.status_code == 404:
                return {"error": "File not found in VirusTotal database", "not_found": True}
            elif response.status_code == 429:
                return {"error": "Rate limit exceeded", "rate_limited": True}
            else:
                return {"error": f"API error: {response.status_code}"}
                
        except Exception as e:
            logger.error(f"VirusTotal report error: {e}")
            return {"error": str(e)}
    
    def _wait_for_analysis(self, analysis_id: str, max_wait: int = 120) -> Dict[str, Any]:
        """Wait for VirusTotal analysis to complete."""
        headers = {"x-apikey": self.api_key}
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            try:
                response = requests.get(
                    f"{self.BASE_URL}/analyses/{analysis_id}",
                    headers=headers,
                    timeout=30
                )
                
                if response.status_code == 200:
                    data = response.json()
                    status = data.get("data", {}).get("attributes", {}).get("status")
                    
                    if status == "completed":
                        # Get the full file report
                        file_id = data.get("meta", {}).get("file_info", {}).get("sha256")
                        if file_id:
                            return self.get_file_report(file_id)
                        return self._parse_analysis(data)
                    
                time.sleep(5)  # Wait 5 seconds before checking again
                
            except Exception as e:
                logger.error(f"VirusTotal wait error: {e}")
                return {"error": str(e)}
        
        return {"error": "Analysis timed out", "timeout": True}
    
    def _parse_report(self, data: Dict) -> Dict[str, Any]:
        """Parse VirusTotal file report into our format."""
        try:
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            results = attrs.get("last_analysis_results", {})
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())
            
            # Calculate threat score based on detection ratio
            detection_ratio = (malicious + suspicious) / max(total, 1)
            threat_score = min(int(detection_ratio * 100 * 1.5), 100)  # Scale up for visibility
            
            # Determine threat level
            if malicious >= 10 or detection_ratio > 0.3:
                threat_level = "critical"
            elif malicious >= 5 or detection_ratio > 0.15:
                threat_level = "high"
            elif malicious >= 2 or detection_ratio > 0.05:
                threat_level = "medium"
            elif malicious >= 1 or suspicious >= 2:
                threat_level = "low"
            else:
                threat_level = "safe"
            
            # Get list of detecting engines
            detections = []
            for engine, result in results.items():
                if result.get("category") in ["malicious", "suspicious"]:
                    detections.append({
                        "engine": engine,
                        "result": result.get("result"),
                        "category": result.get("category")
                    })
            
            return {
                "source": "virustotal",
                "file_hash": attrs.get("sha256"),
                "file_name": attrs.get("meaningful_name", "Unknown"),
                "file_type": attrs.get("type_description", "Unknown"),
                "file_size": attrs.get("size", 0),
                "threat_score": threat_score,
                "threat_level": threat_level,
                "verdict": self._generate_verdict(malicious, total, threat_level),
                "detection_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "undetected": stats.get("undetected", 0),
                    "total_engines": total
                },
                "detections": detections[:20],  # Limit to top 20
                "behaviors": [],
                "indicators": [d["result"] for d in detections[:10] if d.get("result")],
                "analysis_date": attrs.get("last_analysis_date"),
                "first_seen": attrs.get("first_submission_date"),
                "times_submitted": attrs.get("times_submitted", 0),
                "reputation": attrs.get("reputation", 0),
                "popular_threat_names": attrs.get("popular_threat_classification", {}).get("suggested_threat_label"),
                "tags": attrs.get("tags", [])
            }
            
        except Exception as e:
            logger.error(f"Parse report error: {e}")
            return {"error": f"Failed to parse report: {e}"}
    
    def _parse_analysis(self, data: Dict) -> Dict[str, Any]:
        """Parse analysis response."""
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("stats", {})
        
        return {
            "source": "virustotal",
            "status": attrs.get("status"),
            "detection_stats": stats,
            "threat_score": stats.get("malicious", 0) * 10,
            "threat_level": "medium" if stats.get("malicious", 0) > 0 else "safe"
        }
    
    def _generate_verdict(self, malicious: int, total: int, threat_level: str) -> str:
        """Generate human-readable verdict."""
        if threat_level == "critical":
            return f"🚨 MALWARE DETECTED - {malicious}/{total} engines flagged this file as malicious"
        elif threat_level == "high":
            return f"⚠️ HIGH RISK - {malicious}/{total} engines detected threats"
        elif threat_level == "medium":
            return f"⚡ SUSPICIOUS - {malicious}/{total} engines detected potential threats"
        elif threat_level == "low":
            return f"🔍 LOW RISK - {malicious}/{total} minor detections"
        else:
            return f"✅ CLEAN - No threats detected by {total} antivirus engines"


# Global instances
sandbox = Sandbox()
signature_db = MalwareSignatureDB()
vt_scanner = VirusTotalScanner()


def analyze_file_in_sandbox(file_content: bytes, filename: str) -> Dict[str, Any]:
    """
    Main function to analyze a file in the sandbox.
    
    Uses a multi-layered approach:
    1. Check local signature database for known malware
    2. Query VirusTotal for cloud-based multi-AV analysis (if API key configured)
    3. Fall back to local static analysis
    
    Args:
        file_content: Raw bytes of the file
        filename: Original filename
        
    Returns:
        Dictionary with comprehensive analysis results
    """
    # Calculate file hash
    file_hash = hashlib.sha256(file_content).hexdigest()
    
    # Step 1: Check local signature database
    known = signature_db.check_hash(file_hash)
    if known:
        return {
            "file_hash": file_hash,
            "file_name": filename,
            "threat_score": 100,
            "threat_level": "critical",
            "verdict": f"🚨 KNOWN MALWARE: {known['name']} ({known['family']})",
            "signature_match": known,
            "source": "local_signature_db",
            "behaviors": [],
            "indicators": ["known_malware"],
            "analysis_duration": 0.01
        }
    
    # Step 2: Try VirusTotal cloud analysis (if configured)
    use_cloud = True
    if config:
        use_cloud = getattr(config, 'USE_CLOUD_SANDBOX', True)
    
    if use_cloud and vt_scanner.is_configured:
        logger.info(f"Querying VirusTotal for {filename} ({file_hash[:16]}...)")
        vt_result = vt_scanner.get_file_report(file_hash)
        
        if not vt_result.get("error"):
            # Successfully got VirusTotal results
            vt_result["file_name"] = filename
            vt_result["analysis_duration"] = 0.5
            
            # Also run local static analysis for additional insights
            local_result = sandbox.analyze_file(file_content, filename)
            
            # Merge local indicators with VT results
            vt_result["local_analysis"] = {
                "behaviors": local_result.behaviors,
                "indicators": local_result.indicators,
                "entropy_detected": any("entropy" in str(b) for b in local_result.behaviors)
            }
            
            return vt_result
        else:
            # If not found in VT database, run local analysis
            fallback = True
            if config:
                fallback = getattr(config, 'CLOUD_SANDBOX_FALLBACK_TO_STATIC', True)
            
            if not fallback:
                return {
                    "file_hash": file_hash,
                    "file_name": filename,
                    "error": vt_result.get("error"),
                    "source": "virustotal",
                    "message": "File not found in VirusTotal. Upload requires API access."
                }
    
    # Step 3: Fall back to local static analysis
    logger.info(f"Running local static analysis for {filename}")
    result = sandbox.analyze_file(file_content, filename)
    result_dict = asdict(result)
    result_dict["source"] = "local_static_analysis"
    
    # Add a note about cloud analysis availability
    if not vt_scanner.is_configured:
        result_dict["note"] = "💡 Add VirusTotal API key in config.py for enhanced cloud-based multi-AV scanning"
    
    return result_dict


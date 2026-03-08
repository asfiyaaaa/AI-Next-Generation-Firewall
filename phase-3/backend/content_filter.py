"""
Content Filtering and File Blocking Module
Provides file type blocking, content inspection, and DLP policies.
"""

import re
import hashlib
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class ContentAnalysisResult:
    filename: str
    file_size: int
    file_type: str
    mime_type: str
    is_blocked: bool
    block_reason: Optional[str]
    dlp_violations: List[Dict[str, Any]]
    threat_indicators: List[str]
    analysis_timestamp: str


# File signatures (magic bytes)
FILE_SIGNATURES = {
    b'\x4D\x5A': ('exe', 'application/x-msdownload'),
    b'\x50\x4B\x03\x04': ('zip', 'application/zip'),
    b'\x25\x50\x44\x46': ('pdf', 'application/pdf'),
    b'\x89\x50\x4E\x47': ('png', 'image/png'),
    b'\xFF\xD8\xFF': ('jpg', 'image/jpeg'),
    b'\x47\x49\x46\x38': ('gif', 'image/gif'),
    b'\xD0\xCF\x11\xE0': ('doc', 'application/msword'),
    b'\x50\x4B\x03\x04\x14\x00\x06\x00': ('docx', 'application/vnd.openxmlformats'),
    b'\x7F\x45\x4C\x46': ('elf', 'application/x-elf'),
    b'\x52\x61\x72\x21': ('rar', 'application/x-rar-compressed'),
}


class ContentFilter:
    # No default blocked extensions - all managed via API
    DEFAULT_BLOCKED = []
    
    # DLP patterns (these are detection patterns, not data)
    DLP_PATTERNS = {
        'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'phone': r'\b(?:\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b',
        'api_key': r'\b[A-Za-z0-9]{32,}\b',
    }
    
    def __init__(self):
        self.blocked_extensions = set()  # Empty by default - configure via API
        self.blocked_mimes: List[str] = []
        self.max_file_size = 100 * 1024 * 1024  # 100MB
        self.dlp_enabled = True
        self.content_keywords: List[str] = []
    
    def analyze_file(self, content: bytes, filename: str) -> ContentAnalysisResult:
        """Analyze file content for blocking and DLP violations."""
        file_type, mime_type = self._detect_type(content, filename)
        ext = '.' + filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        
        is_blocked, block_reason = False, None
        dlp_violations, threat_indicators = [], []
        
        # Check size
        if len(content) > self.max_file_size:
            is_blocked, block_reason = True, f"File exceeds max size ({self.max_file_size//1024//1024}MB)"
        
        # Check extension
        elif ext in self.blocked_extensions:
            is_blocked, block_reason = True, f"Blocked extension: {ext}"
        
        # Check MIME type
        elif mime_type in self.blocked_mimes:
            is_blocked, block_reason = True, f"Blocked MIME type: {mime_type}"
        
        # DLP scan
        if self.dlp_enabled and not is_blocked:
            try:
                text = content.decode('utf-8', errors='ignore')
                for name, pattern in self.DLP_PATTERNS.items():
                    matches = re.findall(pattern, text)
                    if matches:
                        dlp_violations.append({'type': name, 'count': len(matches)})
                        threat_indicators.append(f'dlp_{name}')
            except: pass
        
        # Keyword scan
        if self.content_keywords:
            try:
                text = content.decode('utf-8', errors='ignore').lower()
                for kw in self.content_keywords:
                    if kw.lower() in text:
                        threat_indicators.append(f'keyword_{kw}')
            except: pass
        
        return ContentAnalysisResult(
            filename=filename,
            file_size=len(content),
            file_type=file_type,
            mime_type=mime_type,
            is_blocked=is_blocked,
            block_reason=block_reason,
            dlp_violations=dlp_violations,
            threat_indicators=threat_indicators,
            analysis_timestamp=datetime.utcnow().isoformat()
        )
    
    def _detect_type(self, content: bytes, filename: str) -> tuple:
        """Detect file type from magic bytes and extension."""
        for sig, (ftype, mime) in FILE_SIGNATURES.items():
            if content.startswith(sig):
                return ftype, mime
        
        ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else 'unknown'
        return ext, f'application/{ext}'
    
    def block_extension(self, ext: str):
        if not ext.startswith('.'): ext = '.' + ext
        self.blocked_extensions.add(ext.lower())
    
    def unblock_extension(self, ext: str):
        if not ext.startswith('.'): ext = '.' + ext
        self.blocked_extensions.discard(ext.lower())
    
    def get_blocked_extensions(self) -> List[str]:
        return sorted(self.blocked_extensions)
    
    def add_keyword(self, keyword: str):
        if keyword not in self.content_keywords:
            self.content_keywords.append(keyword)
    
    def get_config(self) -> Dict[str, Any]:
        return {
            'blocked_extensions': self.get_blocked_extensions(),
            'blocked_mimes': self.blocked_mimes,
            'max_file_size_mb': self.max_file_size // 1024 // 1024,
            'dlp_enabled': self.dlp_enabled,
            'content_keywords': self.content_keywords
        }


# Global instance
content_filter = ContentFilter()

def analyze_content(content: bytes, filename: str) -> Dict[str, Any]:
    return asdict(content_filter.analyze_file(content, filename))

def get_filter_config() -> Dict[str, Any]:
    return content_filter.get_config()

def update_filter_config(blocked_exts: List[str] = None, max_size_mb: int = None,
                        dlp_enabled: bool = None) -> Dict[str, Any]:
    if blocked_exts is not None:
        content_filter.blocked_extensions = set(blocked_exts)
    if max_size_mb is not None:
        content_filter.max_file_size = max_size_mb * 1024 * 1024
    if dlp_enabled is not None:
        content_filter.dlp_enabled = dlp_enabled
    return get_filter_config()

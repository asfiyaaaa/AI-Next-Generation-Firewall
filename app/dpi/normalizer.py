"""
Content Normalizer - Stage 1
Safely decodes and normalizes payload content before inspection.
"""
import base64
import html
import urllib.parse
import logging
from typing import Optional, Tuple

from .context import InspectionContext
from .safety import DecodeDepthTracker, safe_decode, is_likely_binary
from .exceptions import DecodeDepthExceededError
from .file_type import detect_file_type

logger = logging.getLogger(__name__)


class ContentNormalizer:
    """
    Stage 1: Content Normalization
    
    Responsibilities:
    - URL decoding
    - Base64 decoding  
    - HTML entity decoding
    - File type detection by magic bytes
    - Double-decode attack prevention (max 3 levels)
    - Deterministic size capping
    
    This stage is FOUNDATIONAL and must be idempotent.
    """
    
    def __init__(self):
        self._depth_tracker = DecodeDepthTracker()
    
    def normalize(self, ctx: InspectionContext) -> None:
        """
        Normalize the raw payload in the context.
        Updates ctx with normalized_payload, decoded_text, and detected types.
        """
        raw = ctx.raw_payload
        
        # Detect file type from magic bytes
        ctx.detected_file_type = detect_file_type(raw)
        
        # Check if binary - don't decode binary files
        if is_likely_binary(raw):
            ctx.normalized_payload = raw
            ctx.detected_content_type = "binary"
            logger.debug(f"Binary content detected: {ctx.detected_file_type}")
            return
        
        # Attempt text normalization
        try:
            normalized, decoded_text = self._normalize_text(raw)
            ctx.normalized_payload = normalized
            ctx.decoded_text = decoded_text
            ctx.detected_content_type = "text"
        except DecodeDepthExceededError:
            # Double-decode attack, use original
            logger.warning("Decode depth exceeded - possible double-encoding attack")
            ctx.normalized_payload = raw
            ctx.decoded_text = safe_decode(raw)
            ctx.detected_content_type = "suspicious"
    
    def _normalize_text(self, data: bytes) -> Tuple[bytes, str]:
        """
        Normalize text content with layered decoding.
        Returns (normalized_bytes, decoded_text).
        """
        # First, decode to string
        text = safe_decode(data)
        
        # Apply decodings with depth tracking
        normalized_text = self._apply_decodings(text)
        
        # Convert back to bytes
        normalized_bytes = normalized_text.encode('utf-8', errors='replace')
        
        return normalized_bytes, normalized_text
    
    def _apply_decodings(self, text: str, depth: int = 0) -> str:
        """
        Apply URL, HTML, and Base64 decodings.
        Tracks depth to prevent double-decode attacks.
        """
        if depth >= 3:
            raise DecodeDepthExceededError(depth, 3)
        
        original = text
        
        # URL decode
        text = self._safe_url_decode(text)
        
        # HTML entity decode
        text = self._safe_html_decode(text)
        
        # Base64 decode (if it looks like base64)
        text = self._safe_base64_decode(text)
        
        # If text changed, recurse (but track depth)
        if text != original and depth < 2:
            try:
                text = self._apply_decodings(text, depth + 1)
            except DecodeDepthExceededError:
                pass  # Stop at current level
        
        return text
    
    def _safe_url_decode(self, text: str) -> str:
        """Safely URL decode, handling errors."""
        try:
            # Only decode if URL-encoded patterns are present
            if '%' in text:
                decoded = urllib.parse.unquote(text)
                # Double-check for double encoding
                if '%' in decoded and decoded != text:
                    decoded = urllib.parse.unquote(decoded)
                return decoded
        except Exception as e:
            logger.debug(f"URL decode error: {e}")
        return text
    
    def _safe_html_decode(self, text: str) -> str:
        """Safely decode HTML entities."""
        try:
            if '&' in text and (';' in text or '#' in text):
                return html.unescape(text)
        except Exception as e:
            logger.debug(f"HTML decode error: {e}")
        return text
    
    def _safe_base64_decode(self, text: str) -> str:
        """
        Attempt Base64 decode if text looks like Base64.
        Only decodes if result is valid UTF-8 text.
        """
        # Skip if too short or doesn't look like base64
        if len(text) < 20:
            return text
        
        # Check for base64 pattern (mostly alphanumeric with +/= )
        clean = text.strip()
        if not self._looks_like_base64(clean):
            return text
        
        try:
            # Attempt decode
            decoded_bytes = base64.b64decode(clean, validate=True)
            
            # Only use if result is valid text (not binary)
            if not is_likely_binary(decoded_bytes):
                decoded_text = decoded_bytes.decode('utf-8')
                return decoded_text
        except Exception:
            pass
        
        return text
    
    def _looks_like_base64(self, text: str) -> bool:
        """
        Heuristic check if string looks like Base64.
        """
        if len(text) < 20 or len(text) % 4 != 0:
            return False
        
        # Check character set
        valid_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        text_chars = set(text.rstrip())
        
        if not text_chars.issubset(valid_chars):
            return False
        
        # Should have mostly alphanumeric
        alnum_count = sum(1 for c in text if c.isalnum())
        return alnum_count / len(text) > 0.90

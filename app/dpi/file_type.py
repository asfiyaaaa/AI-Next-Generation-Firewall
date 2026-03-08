"""
File Type Detection by Magic Bytes
Detects content type based on file signatures, not extensions.
"""
from enum import Enum
from typing import Optional


class FileType(str, Enum):
    """Detected file types."""
    # Text formats
    TEXT = "text"
    HTML = "html"
    XML = "xml"
    JSON = "json"
    JAVASCRIPT = "javascript"
    CSS = "css"
    
    # Images
    JPEG = "jpeg"
    PNG = "png"
    GIF = "gif"
    WEBP = "webp"
    BMP = "bmp"
    SVG = "svg"
    ICO = "ico"
    
    # Video/Audio
    MP4 = "mp4"
    WEBM = "webm"
    MP3 = "mp3"
    WAV = "wav"
    
    # Archives
    ZIP = "zip"
    GZIP = "gzip"
    RAR = "rar"
    SEVENZ = "7z"
    TAR = "tar"
    
    # Documents
    PDF = "pdf"
    DOCX = "docx"
    XLSX = "xlsx"
    
    # Executables
    EXE = "exe"
    ELF = "elf"
    MACHO = "macho"
    
    # Data formats
    SQLITE = "sqlite"
    
    # Protocols
    HTTP = "http"
    
    # Unknown
    UNKNOWN = "unknown"
    BINARY = "binary"


# Magic byte signatures (prefix -> file type)
MAGIC_SIGNATURES = {
    # Images
    b'\xff\xd8\xff': FileType.JPEG,
    b'\x89PNG\r\n\x1a\n': FileType.PNG,
    b'GIF87a': FileType.GIF,
    b'GIF89a': FileType.GIF,
    b'RIFF': FileType.WEBP,  # Also could be WAV, need further check
    b'BM': FileType.BMP,
    b'\x00\x00\x01\x00': FileType.ICO,
    
    # Archives
    b'PK\x03\x04': FileType.ZIP,  # Also DOCX, XLSX, etc.
    b'\x1f\x8b': FileType.GZIP,
    b'Rar!\x1a\x07': FileType.RAR,
    b"7z\xbc\xaf'\x1c": FileType.SEVENZ,
    
    # Documents
    b'%PDF': FileType.PDF,
    
    # Executables
    b'MZ': FileType.EXE,
    b'\x7fELF': FileType.ELF,
    b'\xfe\xed\xfa\xce': FileType.MACHO,
    b'\xfe\xed\xfa\xcf': FileType.MACHO,
    b'\xca\xfe\xba\xbe': FileType.MACHO,
    
    # Database
    b'SQLite format 3': FileType.SQLITE,
    
    # Video
    b'\x00\x00\x00\x1cftyp': FileType.MP4,
    b'\x00\x00\x00 ftyp': FileType.MP4,
    b'\x1aE\xdf\xa3': FileType.WEBM,
    
    # Audio
    b'ID3': FileType.MP3,
    b'\xff\xfb': FileType.MP3,
    b'\xff\xfa': FileType.MP3,
}

# Text prefixes that indicate specific formats
TEXT_PREFIXES = {
    b'<!DOCTYPE html': FileType.HTML,
    b'<!doctype html': FileType.HTML,
    b'<html': FileType.HTML,
    b'<HTML': FileType.HTML,
    b'<?xml': FileType.XML,
    b'<svg': FileType.SVG,
    b'{': FileType.JSON,
    b'[': FileType.JSON,
    b'HTTP/': FileType.HTTP,
    b'GET ': FileType.HTTP,
    b'POST ': FileType.HTTP,
    b'PUT ': FileType.HTTP,
    b'DELETE ': FileType.HTTP,
    b'HEAD ': FileType.HTTP,
    b'OPTIONS ': FileType.HTTP,
    b'PATCH ': FileType.HTTP,
}


def detect_file_type(data: bytes) -> str:
    """
    Detect file type based on magic bytes.
    Returns FileType value as string.
    """
    if not data:
        return FileType.UNKNOWN.value
    
    # Check binary magic signatures first
    for magic, file_type in MAGIC_SIGNATURES.items():
        if data.startswith(magic):
            # Special case: ZIP could be DOCX/XLSX
            if file_type == FileType.ZIP and len(data) > 30:
                if b'word/' in data[:500] or b'[Content_Types]' in data[:500]:
                    return FileType.DOCX.value
                if b'xl/' in data[:500]:
                    return FileType.XLSX.value
            return file_type.value
    
    # Check WEBP specifically (RIFF....WEBP)
    if data.startswith(b'RIFF') and len(data) > 12:
        if data[8:12] == b'WEBP':
            return FileType.WEBP.value
        if data[8:12] == b'WAVE':
            return FileType.WAV.value
    
    # Check text-based formats
    # Strip leading whitespace for text detection
    stripped = data.lstrip()
    for prefix, file_type in TEXT_PREFIXES.items():
        if stripped.startswith(prefix):
            return file_type.value
    
    # Check if it's likely text
    if _is_likely_text(data):
        # Try to detect specific text types
        text = data[:1000].decode('utf-8', errors='ignore').lower()
        
        if 'function ' in text or 'var ' in text or 'const ' in text:
            return FileType.JAVASCRIPT.value
        if '{' in text and (':' in text or '"' in text):
            # Could be JSON or CSS
            if 'background' in text or 'color' in text or 'font' in text:
                return FileType.CSS.value
            return FileType.JSON.value
        if '<' in text and '>' in text:
            if '<html' in text or '<!doctype' in text:
                return FileType.HTML.value
            return FileType.XML.value
        
        return FileType.TEXT.value
    
    return FileType.BINARY.value


def _is_likely_text(data: bytes, sample_size: int = 512) -> bool:
    """
    Heuristic check if data is likely text content.
    """
    sample = data[:sample_size]
    
    # Null bytes indicate binary
    if b'\x00' in sample:
        return False
    
    # Count printable ASCII characters
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    ratio = printable / len(sample) if sample else 0
    
    return ratio > 0.75


def is_executable(data: bytes) -> bool:
    """Check if data is an executable binary."""
    file_type = detect_file_type(data)
    return file_type in (FileType.EXE.value, FileType.ELF.value, FileType.MACHO.value)


def is_archive(data: bytes) -> bool:
    """Check if data is an archive."""
    file_type = detect_file_type(data)
    return file_type in (
        FileType.ZIP.value, FileType.GZIP.value, 
        FileType.RAR.value, FileType.SEVENZ.value,
        FileType.TAR.value
    )


def is_document(data: bytes) -> bool:
    """Check if data is a document."""
    file_type = detect_file_type(data)
    return file_type in (
        FileType.PDF.value, FileType.DOCX.value, FileType.XLSX.value
    )

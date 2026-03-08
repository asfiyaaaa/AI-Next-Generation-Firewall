"""
DPI Core Exceptions
Custom exceptions for DPI processing errors.
"""


class DPIError(Exception):
    """Base exception for all DPI errors."""
    pass


class PayloadTooLargeError(DPIError):
    """Raised when payload exceeds maximum allowed size."""
    def __init__(self, size: int, max_size: int):
        self.size = size
        self.max_size = max_size
        super().__init__(f"Payload size {size} exceeds maximum {max_size}")


class DecodeDepthExceededError(DPIError):
    """Raised when decode depth exceeds maximum allowed levels."""
    def __init__(self, depth: int, max_depth: int):
        self.depth = depth
        self.max_depth = max_depth
        super().__init__(f"Decode depth {depth} exceeds maximum {max_depth}")


class InvalidPayloadError(DPIError):
    """Raised when payload cannot be processed."""
    pass


class SignatureCompilationError(DPIError):
    """Raised when a signature pattern fails to compile."""
    def __init__(self, pattern: str, reason: str):
        self.pattern = pattern
        self.reason = reason
        super().__init__(f"Failed to compile pattern '{pattern}': {reason}")


class RegexTimeoutError(DPIError):
    """Raised when regex matching times out (ReDoS protection)."""
    def __init__(self, pattern_id: str):
        self.pattern_id = pattern_id
        super().__init__(f"Regex timeout for pattern {pattern_id}")

class ThreatIntelError(DPIError):
    """Raised when threat intelligence lookup fails."""
    pass


class PipelineError(DPIError):
    """Raised when pipeline execution fails at a stage."""
    def __init__(self, stage: str, reason: str):
        self.stage = stage
        self.reason = reason
        super().__init__(f"Pipeline failed at stage '{stage}': {reason}")

class ConfigurationError(DPIError):
    """Raised when configuration is invalid."""
    pass

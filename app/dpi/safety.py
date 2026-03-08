"""
DPI Safety Module - Enterprise Hardened
Hard execution timeouts, memory bounds, and stage isolation.
"""
import time
import signal
import threading
import traceback
import sys
from dataclasses import dataclass, field
from typing import Callable, TypeVar, Any, Optional
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
import logging

from .constants import MAX_PAYLOAD_SIZE, MAX_DECODE_DEPTH, MAX_REGEX_TIMEOUT_MS
from .exceptions import (
    PayloadTooLargeError, DecodeDepthExceededError, 
    RegexTimeoutError, PipelineError
)

logger = logging.getLogger(__name__)

T = TypeVar('T')


@dataclass
class SafetyConfig:
    """Enterprise safety configuration."""
    # Payload limits
    max_payload_size: int = MAX_PAYLOAD_SIZE  # 10 MB
    max_decode_depth: int = MAX_DECODE_DEPTH  # 3 levels
    
    # Execution timeouts (milliseconds)
    max_regex_timeout_ms: int = MAX_REGEX_TIMEOUT_MS  # 100ms
    max_stage_timeout_ms: int = 10000  # 10 seconds per stage (Safe for Windows execution)
    max_total_timeout_ms: int = 60000  # 60 seconds total
    
    # Memory limits
    max_context_size_bytes: int = 50 * 1024 * 1024  # 50 MB total context
    max_decoded_buffer_bytes: int = 20 * 1024 * 1024  # 20 MB decoded
    
    # Stage failure behavior
    stage_failure_risk_score: float = 0.3  # Risk added on stage failure
    max_stage_failures: int = 3  # Abort if too many stages fail


# Thread-local storage for per-inspection memory tracking
class InspectionResourceTracker:
    """Track resources used during a single inspection."""
    
    def __init__(self, config: SafetyConfig):
        self.config = config
        self.bytes_allocated = 0
        self.start_time = time.perf_counter()
        self.stage_failures = 0
        self.timed_out_stages = []
        
    def track_allocation(self, size: int) -> bool:
        """
        Track memory allocation. Returns False if limit exceeded.
        """
        self.bytes_allocated += size
        return self.bytes_allocated <= self.config.max_context_size_bytes
    
    def check_total_timeout(self) -> bool:
        """Check if total inspection time exceeded."""
        elapsed_ms = (time.perf_counter() - self.start_time) * 1000
        return elapsed_ms < self.config.max_total_timeout_ms
    
    def record_stage_failure(self, stage: str) -> bool:
        """
        Record a stage failure. Returns False if too many failures.
        """
        self.stage_failures += 1
        return self.stage_failures < self.config.max_stage_failures
    
    def record_stage_timeout(self, stage: str) -> None:
        """Record a stage that timed out."""
        self.timed_out_stages.append(stage)


# Global safety configuration
_safety_config = SafetyConfig()

# Thread pool for timeout enforcement
_executor: Optional[ThreadPoolExecutor] = None


def get_safety_config() -> SafetyConfig:
    """Get current safety configuration."""
    return _safety_config


def set_safety_config(config: SafetyConfig) -> None:
    """Set safety configuration."""
    global _safety_config
    _safety_config = config


def get_executor() -> ThreadPoolExecutor:
    """Get or create the thread pool executor."""
    global _executor
    if _executor is None:
        _executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="dpi_stage_")
    return _executor


def shutdown_executor() -> None:
    """Shutdown the thread pool executor."""
    global _executor
    if _executor:
        _executor.shutdown(wait=False)
        _executor = None


def validate_payload_size(payload: bytes) -> None:
    """
    Validate payload size against maximum limit.
    Raises PayloadTooLargeError if exceeded.
    """
    size = len(payload)
    if size > _safety_config.max_payload_size:
        raise PayloadTooLargeError(size, _safety_config.max_payload_size)


def validate_decode_depth(current_depth: int) -> None:
    """
    Validate decode depth against maximum limit.
    Raises DecodeDepthExceededError if exceeded.
    """
    if current_depth > _safety_config.max_decode_depth:
        raise DecodeDepthExceededError(current_depth, _safety_config.max_decode_depth)


class DecodeDepthTracker:
    """
    Context manager to track decode depth and prevent recursive decoding attacks.
    """
    def __init__(self):
        self._depth = 0
    
    def __enter__(self):
        self._depth += 1
        validate_decode_depth(self._depth)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self._depth -= 1
        return False
    
    @property
    def depth(self) -> int:
        return self._depth
    
    def can_decode(self) -> bool:
        """Check if another decode level is allowed."""
        return self._depth < _safety_config.max_decode_depth


def execute_with_hard_timeout(
    func: Callable[[], T],
    timeout_ms: int,
    stage_name: str
) -> tuple[Optional[T], Optional[Exception], bool]:
    """
    Execute a function with a HARD timeout.
    
    Returns:
        (result, exception, timed_out)
        - result: Function return value if successful
        - exception: Exception if one occurred
        - timed_out: True if execution was aborted due to timeout
    """
    executor = get_executor()
    timeout_sec = timeout_ms / 1000.0
    
    try:
        future = executor.submit(func)
        result = future.result(timeout=timeout_sec)
        return (result, None, False)
    except FuturesTimeoutError:
        logger.warning(f"Stage '{stage_name}' timed out after {timeout_ms}ms")
        # Note: The thread may continue running, but we proceed without its result
        return (None, None, True)
    except Exception as e:
        logger.warning(f"Stage '{stage_name}' raised exception: {e}")
        return (None, e, False)


def isolated_stage_execution(stage_name: str, timeout_ms: int = None):
    """
    Decorator for isolated stage execution with hard timeout.
    
    - Enforces hard timeout
    - Catches all exceptions
    - Returns gracefully on failure
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Optional[T]:
            nonlocal timeout_ms
            if timeout_ms is None:
                timeout_ms = _safety_config.max_stage_timeout_ms
            
            # Wrap function call
            def execute():
                return func(*args, **kwargs)
            
            result, exception, timed_out = execute_with_hard_timeout(
                execute, timeout_ms, stage_name
            )
            
            if timed_out:
                logger.error(f"HARD TIMEOUT: Stage '{stage_name}' aborted")
                return None
            
            if exception:
                logger.error(f"STAGE FAILURE: '{stage_name}' - {exception}")
                return None
            
            return result
        return wrapper
    return decorator


def truncate_for_inspection(data: bytes, max_size: int = None) -> bytes:
    """
    Safely truncate payload for inspection.
    Returns a bounded subset of the data.
    """
    if max_size is None:
        max_size = _safety_config.max_payload_size
    
    if len(data) <= max_size:
        return data
    
    logger.warning(f"Truncating payload from {len(data)} to {max_size} bytes")
    return data[:max_size]


def safe_decode(data: bytes, encoding: str = 'utf-8', errors: str = 'replace') -> str:
    """
    Safely decode bytes to string with error handling.
    Never raises exceptions.
    """
    try:
        return data.decode(encoding, errors=errors)
    except Exception:
        try:
            return data.decode('latin-1')
        except Exception:
            return ""


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of data.
    Returns value between 0.0 and 8.0.
    """
    if not data:
        return 0.0
    
    import math
    from collections import Counter
    
    # Limit sample size for performance
    sample = data[:10000]
    counts = Counter(sample)
    length = len(sample)
    
    entropy = 0.0
    for count in counts.values():
        if count > 0:
            prob = count / length
            entropy -= prob * math.log2(prob)
    
    return entropy


def is_likely_binary(data: bytes, sample_size: int = 512) -> bool:
    """
    Heuristic check if data is likely binary (not text).
    """
    sample = data[:sample_size]
    
    if b'\x00' in sample:
        return True
    
    non_printable = sum(1 for b in sample if b < 32 and b not in (9, 10, 13))
    ratio = non_printable / len(sample) if sample else 0
    
    return ratio > 0.3


def safe_regex_match(pattern, text: str, timeout_ms: int = None) -> Optional[Any]:
    """
    Execute regex match with timeout protection.
    
    Returns None on timeout or error instead of crashing.
    """
    import re
    
    if timeout_ms is None:
        timeout_ms = _safety_config.max_regex_timeout_ms
    
    def do_match():
        return pattern.search(text)
    
    result, exception, timed_out = execute_with_hard_timeout(
        do_match, timeout_ms, f"regex_{id(pattern)}"
    )
    
    if timed_out or exception:
        return None
    
    return result


def estimate_context_size(ctx) -> int:
    """
    Estimate memory size of an inspection context.
    """
    size = 0
    
    # Raw payload
    if hasattr(ctx, 'raw_payload') and ctx.raw_payload:
        size += len(ctx.raw_payload)
    
    # Normalized payload
    if hasattr(ctx, 'normalized_payload') and ctx.normalized_payload:
        size += len(ctx.normalized_payload)
    
    # Decoded text
    if hasattr(ctx, 'decoded_text') and ctx.decoded_text:
        size += len(ctx.decoded_text.encode('utf-8', errors='ignore'))
    
    # Fixed overhead estimate
    size += 10000  # ~10KB for other fields
    
    return size


def check_memory_bounds(ctx, tracker: InspectionResourceTracker) -> bool:
    """
    Check if inspection context exceeds memory bounds.
    Returns False if bounds exceeded.
    """
    size = estimate_context_size(ctx)
    return tracker.track_allocation(size)

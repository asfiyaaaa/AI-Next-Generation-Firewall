"""
DPI Core Module
"""
from .constants import (
    Decision, Severity, ContentType, AttackType, 
    Protocol, DPIStage, MAX_PAYLOAD_SIZE, MIN_BLOCK_CONFIDENCE
)
from .context import (
    InspectionContext, ConnectionMetadata, TLSMetadata,
    ApplicationResult, SignatureMatch, SignatureResult,
    IPSResult, TLSInspectionResult, AnomalyResult, ThreatIntelResult
)
from .verdict import DPIVerdict, aggregate_verdict
from .exceptions import (
    DPIError, PayloadTooLargeError, DecodeDepthExceededError,
    InvalidPayloadError, SignatureCompilationError,
    RegexTimeoutError, ThreatIntelError, PipelineError, ConfigurationError
)
from .safety import (
    SafetyConfig, get_safety_config, set_safety_config,
    validate_payload_size, validate_decode_depth,
    DecodeDepthTracker, execute_with_hard_timeout, isolated_stage_execution,
    truncate_for_inspection, safe_decode,
    calculate_entropy, is_likely_binary,
    InspectionResourceTracker, check_memory_bounds
)

__all__ = [
    # Constants
    'Decision', 'Severity', 'ContentType', 'AttackType',
    'Protocol', 'DPIStage', 'MAX_PAYLOAD_SIZE', 'MIN_BLOCK_CONFIDENCE',
    # Context
    'InspectionContext', 'ConnectionMetadata', 'TLSMetadata',
    'ApplicationResult', 'SignatureMatch', 'SignatureResult',
    'IPSResult', 'TLSInspectionResult', 'AnomalyResult', 'ThreatIntelResult',
    # Verdict
    'DPIVerdict', 'aggregate_verdict',
    # Exceptions
    'DPIError', 'PayloadTooLargeError', 'DecodeDepthExceededError',
    'InvalidPayloadError', 'SignatureCompilationError',
    'RegexTimeoutError', 'ThreatIntelError', 'PipelineError', 'ConfigurationError',
    # Safety
    'SafetyConfig', 'get_safety_config', 'set_safety_config',
    'validate_payload_size', 'validate_decode_depth',
    'DecodeDepthTracker', 'execute_with_hard_timeout', 'isolated_stage_execution',
    'truncate_for_inspection', 'safe_decode',
    'calculate_entropy', 'is_likely_binary',
    'InspectionResourceTracker', 'check_memory_bounds',
]

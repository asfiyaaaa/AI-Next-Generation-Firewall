"""
DPI Engine - Enterprise Hardened
8-stage pipeline with isolated execution, hard timeouts, and graceful degradation.
"""
import logging
import time
from typing import Optional

from .context import InspectionContext, ConnectionMetadata, TLSMetadata
from .verdict import DPIVerdict, aggregate_verdict
from .constants import ContentType, DPIStage
from .safety import (
    validate_payload_size, truncate_for_inspection,
    SafetyConfig, get_safety_config, InspectionResourceTracker,
    execute_with_hard_timeout, check_memory_bounds
)
from .exceptions import PipelineError, DPIError

logger = logging.getLogger(__name__)


class DPIEngine:
    """
    Enterprise-Hardened DPI Engine.
    
    Executes the mandatory 8-stage pipeline with:
    - Hard per-stage timeouts
    - Stage-level failure isolation
    - Memory bounds enforcement
    - Graceful degradation on failures
    
    PIPELINE ORDER (MANDATORY):
    1. Content Normalization
    2. Application Identification
    3. TLS Inspection
    4. Signature Matching
    5. IPS
    6. Protocol Anomaly
    7. Threat Intelligence
    8. Verdict Aggregation
    """
    
    def __init__(self):
        """Initialize DPI engine."""
        self._initialized = False
        self._normalizer = None
        self._app_identifier = None
        self._tls_inspector = None
        self._signature_engine = None
        self._ips_engine = None
        self._anomaly_engine = None
        self._threat_intel = None
        self._config = get_safety_config()
        
    def initialize(self) -> None:
        """
        Initialize all DPI stage handlers.
        Must be called before inspect().
        """
        from .normalizer import ContentNormalizer
        from .app_identifier import ApplicationIdentifier
        from .tls_inspector import TLSInspector
        from .signature_engine import SignatureEngine
        from .ips_engine import IPSEngine
        from .anomaly_engine import AnomalyEngine
        from .intel_engine import ThreatIntelEngine
        
        logger.info("Initializing DPI Engine (Enterprise Hardened)...")
        
        self._normalizer = ContentNormalizer()
        self._app_identifier = ApplicationIdentifier()
        self._tls_inspector = TLSInspector()
        self._signature_engine = SignatureEngine()
        self._ips_engine = IPSEngine()
        self._anomaly_engine = AnomalyEngine()
        self._threat_intel = ThreatIntelEngine()
        
        # Initialize signature engine (compile patterns safely)
        try:
            self._signature_engine.initialize()
        except Exception as e:
            logger.error(f"Signature engine initialization failed: {e}")
            # Continue - engine will work without signatures
        
        self._initialized = True
        logger.info("DPI Engine initialized successfully")
    
    def create_context(
        self,
        payload: bytes,
        src_ip: str,
        dst_ip: str,
        protocol: str = "TCP",
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        content_type_hint: ContentType = ContentType.UNKNOWN,
        application_hint: Optional[str] = None,
        tls_metadata: Optional[TLSMetadata] = None
    ) -> InspectionContext:
        """
        Create an InspectionContext from raw inputs.
        Validates and truncates payload to safety limits.
        """
        # Validate size (raises if too large)
        validate_payload_size(payload)
        
        # Truncate to inspection limit
        bounded_payload = truncate_for_inspection(payload)
        
        metadata = ConnectionMetadata(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            application_hint=application_hint,
            tls_metadata=tls_metadata
        )
        
        return InspectionContext(
            raw_payload=bounded_payload,
            content_type_hint=content_type_hint,
            metadata=metadata
        )
    
    def inspect(self, ctx: InspectionContext) -> DPIVerdict:
        """
        Execute the full 8-stage DPI pipeline with enterprise hardening.
        
        GUARANTEES:
        - Each stage has hard timeout
        - Stage failures are isolated
        - Memory bounds are checked
        - Total inspection time is bounded
        - Always returns a valid verdict
        """
        if not self._initialized:
            self.initialize()
        
        # Create resource tracker for this inspection
        tracker = InspectionResourceTracker(self._config)
        
        # Execute pipeline with isolation
        pipeline_stages = [
            (DPIStage.NORMALIZATION, self._normalizer.normalize, "normalization"),
            (DPIStage.APPLICATION_ID, self._app_identifier.identify, "app_id"),
            (DPIStage.TLS_INSPECTION, self._tls_inspector.inspect, "tls"),
            (DPIStage.SIGNATURE_MATCHING, self._signature_engine.match, "signatures"),
            (DPIStage.IPS, self._ips_engine.detect, "ips"),
            (DPIStage.PROTOCOL_ANOMALY, self._anomaly_engine.detect, "anomaly"),
            (DPIStage.THREAT_INTEL, self._threat_intel.correlate, "threat_intel"),
        ]
        
        for stage_enum, handler, stage_name in pipeline_stages:
            # Check total timeout
            if not tracker.check_total_timeout():
                ctx.add_error(f"Total inspection timeout exceeded")
                logger.warning("Inspection aborted: total timeout exceeded")
                break
            
            # Check memory bounds
            if not check_memory_bounds(ctx, tracker):
                ctx.add_error(f"Memory bounds exceeded")
                logger.warning("Inspection aborted: memory bounds exceeded")
                break
            
            # Execute stage with isolation
            success = self._execute_stage_isolated(
                stage_enum, handler, ctx, tracker
            )
            
            # Check if too many failures
            if not success:
                if not tracker.record_stage_failure(stage_name):
                    ctx.add_error("Too many stage failures")
                    logger.warning("Inspection aborted: too many stage failures")
                    break
        
        # Stage 8: Verdict Aggregation (always runs)
        ctx.mark_stage_complete(DPIStage.VERDICT_AGGREGATION.value)
        return aggregate_verdict(ctx)
    
    def _execute_stage_isolated(
        self,
        stage: DPIStage,
        handler: callable,
        ctx: InspectionContext,
        tracker: InspectionResourceTracker
    ) -> bool:
        """
        Execute a single pipeline stage with full isolation.
        
        Returns True on success, False on failure.
        Failures are recorded in context but don't crash the engine.
        """
        timeout_ms = self._config.max_stage_timeout_ms
        
        def execute():
            handler(ctx)
        
        try:
            result, exception, timed_out = execute_with_hard_timeout(
                execute, timeout_ms, stage.value
            )
            
            if timed_out:
                ctx.add_error(f"{stage.value}: timeout after {timeout_ms}ms")
                tracker.record_stage_timeout(stage.value)
                logger.warning(f"Stage {stage.value} timed out")
                return False
            
            if exception:
                ctx.add_error(f"{stage.value}: {type(exception).__name__}")
                logger.warning(f"Stage {stage.value} failed: {exception}")
                return False
            
            ctx.mark_stage_complete(stage.value)
            return True
            
        except Exception as e:
            # Catch-all for any unexpected errors
            ctx.add_error(f"{stage.value}: unexpected error")
            logger.exception(f"Stage {stage.value} unexpected failure: {e}")
            return False


# Global engine instance
_engine: Optional[DPIEngine] = None


def get_engine() -> DPIEngine:
    """Get or create the global DPI engine instance."""
    global _engine
    if _engine is None:
        _engine = DPIEngine()
    return _engine


def inspect_payload(
    payload: bytes,
    src_ip: str,
    dst_ip: str,
    protocol: str = "TCP",
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    content_type_hint: str = "unknown",
    application_hint: Optional[str] = None,
    tls_sni: Optional[str] = None,
    tls_ja3: Optional[str] = None,
    tls_cert_cn: Optional[str] = None,
    tls_alpn: Optional[str] = None
) -> DPIVerdict:
    """
    Convenience function to inspect a payload.
    Creates context and runs full pipeline.
    """
    engine = get_engine()
    
    try:
        ct = ContentType(content_type_hint)
    except ValueError:
        ct = ContentType.UNKNOWN
    
    tls_metadata = None
    if any([tls_sni, tls_ja3, tls_cert_cn, tls_alpn]):
        tls_metadata = TLSMetadata(
            sni=tls_sni,
            ja3=tls_ja3,
            cert_cn=tls_cert_cn,
            alpn=tls_alpn
        )
    
    ctx = engine.create_context(
        payload=payload,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        content_type_hint=ct,
        application_hint=application_hint,
        tls_metadata=tls_metadata
    )
    
    return engine.inspect(ctx)

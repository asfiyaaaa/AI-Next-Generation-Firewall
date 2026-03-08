
import sys
import threading
import time
import signal
import logging

import argparse
from pathlib import Path

# Ensure the current directory is in sys.path
sys.path.append(str(Path(__file__).parent))

from app.core.capture import WinDivertCapture, MockWinDivertCapture
from app.core.rules import RuleEngine
from app.core.nat import NATEngine
from app.core.connection import ConnectionTable
from app.core.pipeline import PipelineProcessor
from app.dpi.engine import get_engine as get_dpi_engine
from app.security_analyzer import create_security_analyzer, InlineSecurityAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('NGFW')

# Set application signatures path for DPI engine
import os
os.environ["APP_SIGNATURES_FILE"] = "config/app_signatures.json"


def main():
    parser = argparse.ArgumentParser(description="NGFW - Fully Automated Security Pipeline")
    parser.add_argument('--filter', default='ip', help='WinDivert filter expression')
    parser.add_argument('--test', action='store_true', help='Run in test mode (Mock Capture)')
    parser.add_argument('--ignore-loopback', action='store_true', help='Suppress local loopback traffic logs')
    parser.add_argument('--no-security', action='store_true', help='Disable Phase-3 security analysis')
    args = parser.parse_args()

    logger.info("="*60)
    logger.info("NGFW - Next Generation Firewall")
    logger.info("Fully Automated Security Pipeline")
    logger.info("="*60)
    logger.info("")
    logger.info("Pipeline: Capture -> L3/L4 -> DPI -> Reassembly -> Security")
    logger.info("")

    # ===== PHASE 1: Core Components =====
    logger.info("[PHASE 1] Initializing Core Processing...")
    
    conn_table = ConnectionTable(max_connections=1000000)
    conn_table.start_cleanup_thread()
    
    from app.core.rules import DefaultRules
    rule_engine = RuleEngine()
    
    # Load rules from config
    try:
        from app.core.rules import RuleParser
        import json
        config_path = Path("config/firewall_rules.json")
        if config_path.exists():
            rule_parser = RuleParser()
            parsed_rules = rule_parser.parse_file(str(config_path))
            for rule in parsed_rules:
                rule_engine.add_rule(rule)
            
            if rule_parser.errors:
                for err in rule_parser.errors:
                    logger.error(f"Rule Config Error: {err}")
            
            logger.info(f"  Loaded {len(parsed_rules)} firewall rules")
        else:
            logger.warning(f"  Config not found, using default rules")
            rule_engine.add_rule(DefaultRules.allow_established())
            rule_engine.add_rule(DefaultRules.allow_loopback())
            rule_engine.add_rule(DefaultRules.drop_invalid())
            rule_engine.add_rule(DefaultRules.allow_icmp())
            rule_engine.add_rule(DefaultRules.allow_dns())
            rule_engine.add_rule(DefaultRules.default_drop())
    except Exception as e:
        logger.error(f"  Failed to load rules: {e}")
        rule_engine.add_rule(DefaultRules.allow_established())
        rule_engine.add_rule(DefaultRules.default_drop())
    
    logger.info("  [OK] L3/L4 Rule Engine ready")
    
    # ===== PHASE 2: DPI Engine =====
    logger.info("[PHASE 2] Initializing Deep Packet Inspection...")
    
    dpi_engine = get_dpi_engine()
    try:
        dpi_engine.initialize()
        logger.info("  [OK] DPI Engine ready (AppID, Protocol Detection)")
    except Exception as e:
        logger.error(f"  DPI Engine failed: {e}")
    
    # ===== PHASE 3: Security Analyzer (Fully Automated) =====
    logger.info("[PHASE 3] Initializing Security Analyzer...")
    
    security_callback = None
    if not args.no_security:
        try:
            # Create fully automated inline security analyzer
            # NO HTTP APIs - all processing is in-process
            security_callback = create_security_analyzer(enable_all=True)
            
            logger.info("  [OK] Security Analyzer ready (FULLY AUTOMATED)")
            logger.info("       - URL Filtering: ENABLED (blocklist-based)")
            logger.info("       - Malware Detection: ENABLED (ML + signatures)")
            logger.info("       - Content Filtering: ENABLED (pattern matching)")
            logger.info("       - NO external APIs required")
        except Exception as e:
            logger.warning(f"  Security Analyzer disabled: {e}")
    else:
        logger.info("  Security Analyzer disabled by --no-security flag")
    
    # ===== Initialize Pipeline =====
    logger.info("[PIPELINE] Connecting all phases...")
    
    pipeline = PipelineProcessor(
        connection_table=conn_table,
        rule_engine=rule_engine,
        enable_dpi=True,
        ignore_loopback=args.ignore_loopback,
        phase3_callback=security_callback
    )
    
    logger.info("  [OK] Pipeline ready: Capture -> L3/L4 -> DPI -> Reassembly -> Security")
    
    # ===== Start Packet Capture =====
    CaptureBackend = MockWinDivertCapture if args.test else WinDivertCapture
    capture = CaptureBackend(filter_expr=args.filter)
    
    if not args.test and not capture.is_available():
        logger.critical("WinDivert not available. Please install it or run with --test.")
        return 1

    logger.info("")
    logger.info("="*60)
    logger.info(f"STARTING {'MOCK' if args.test else 'LIVE'} CAPTURE")
    logger.info(f"Filter: {args.filter}")
    logger.info("="*60)
    logger.info("")
    logger.info("All traffic is now being analyzed automatically.")
    logger.info("Threats will be BLOCKED and logged.")
    logger.info("Press Ctrl+C to stop.")
    logger.info("")
    
    # Helper to print stats
    def log_stats(header="Final Statistics"):
        cap_stats = capture.stats.to_dict()
        pipe_stats = pipeline.get_stats()
        
        l3_dropped = pipe_stats['l3_dropped']
        l3_allowed = pipe_stats['l3_allowed']
        dpi_dropped = pipe_stats['dpi_dropped']
        final_allowed = pipe_stats.get('final_allowed', 0)
        
        # Get security stats
        sec_stats = security_callback.get_stats() if security_callback else {}
        
        logger.info(
            f"\n{'='*60}\n"
            f"               {header}                \n"
            f"{'='*60}\n"
            f"PACKET CAPTURE:\n"
            f"  Total Captured:      {cap_stats['packets_captured']}\n"
            f"  Data Volume:         {cap_stats['bytes_captured']} bytes\n"
            f"  Capture Rate:        {cap_stats['packets_per_second']} pps\n"
            f"  Errors:              {cap_stats['errors']}\n\n"
            f"PHASE 1: Core Processing (L3/L4 Rules)\n"
            f"  [DROP] L3 Blocked:   {l3_dropped}\n"
            f"  [PASS] L3 Allowed:   {l3_allowed}  ->  (Sent to Phase 2)\n\n"
            f"PHASE 2: Deep Packet Inspection\n"
            f"  [DROP] DPI Blocked:  {dpi_dropped}\n"
            f"  [PASS] DPI Allowed:  {final_allowed}  ->  (Sent to Phase 3)\n\n"
            f"PHASE 3: Security Analysis (Automated)\n"
            f"  Streams Analyzed:    {sec_stats.get('streams_analyzed', 'N/A')}\n"
            f"  URLs Checked:        {sec_stats.get('urls_checked', 'N/A')}\n"
            f"  Files Analyzed:      {sec_stats.get('files_analyzed', 'N/A')}\n"
            f"  Threats Detected:    {sec_stats.get('threats_detected', 'N/A')}\n"
            f"  Malware Detected:    {sec_stats.get('malware_detected', 'N/A')}\n"
            f"  Blocked URLs:        {sec_stats.get('blocked_urls', 'N/A')}\n"
            f"  Streams BLOCKED:     {sec_stats.get('blocked', 'N/A')}\n"
            f"  Streams ALLOWED:     {sec_stats.get('allowed', 'N/A')}\n\n"
            f"VERDICT SUMMARY:\n"
            f"  Total Blocked:       {l3_dropped + dpi_dropped + sec_stats.get('blocked', 0)}\n"
            f"  Total Allowed:       {final_allowed - sec_stats.get('blocked', 0)}\n"
            f"{'='*60}"
        )

    running = True

    def signal_handler(sig, frame):
        nonlocal running
        logger.info("Stopping firewall...")
        running = False
        capture.stop()
        conn_table.stop_cleanup_thread()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        capture.start(callback=pipeline.process_packet, blocking=True)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.error(f"Capture loop error: {e}")
    finally:
        log_stats("Final Statistics")
        logger.info("Firewall stopped.")
        import os
        os._exit(0)

if __name__ == "__main__":
    main()













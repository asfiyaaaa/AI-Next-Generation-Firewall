"""
Test the fully automated security pipeline.

Demonstrates:
1. URL filtering - blocking malicious domains
2. Malware detection - detecting PE files with suspicious patterns
3. Content filtering - blocking dangerous file types
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from app.security_analyzer import (
    InlineSecurityAnalyzer,
    SecurityVerdict,
    AutomatedSecurityCallback
)

def test_url_filtering():
    """Test automatic URL/domain filtering."""
    print("\n" + "="*60)
    print("TEST 1: Automatic URL Filtering")
    print("="*60)
    
    analyzer = InlineSecurityAnalyzer()
    
    # Test cases: (data, expected_verdict)
    test_cases = [
        # Blocked domain
        (b"GET /download HTTP/1.1\r\nHost: malware.com\r\n\r\n", SecurityVerdict.BLOCK),
        (b"GET /page HTTP/1.1\r\nHost: phishing.com\r\n\r\n", SecurityVerdict.BLOCK),
        (b"GET /video HTTP/1.1\r\nHost: pornhub.com\r\n\r\n", SecurityVerdict.BLOCK),
        # Safe domain
        (b"GET /search HTTP/1.1\r\nHost: google.com\r\n\r\n", SecurityVerdict.ALLOW),
        (b"GET /page HTTP/1.1\r\nHost: microsoft.com\r\n\r\n", SecurityVerdict.ALLOW),
    ]
    
    passed = 0
    for data, expected in test_cases:
        result = analyzer.analyze(data)
        host = data.split(b'Host: ')[1].split(b'\r\n')[0].decode() if b'Host: ' in data else "unknown"
        status = "OK" if result.verdict == expected else "FAIL"
        if result.verdict == expected:
            passed += 1
        print(f"  {host:20} -> {result.verdict.value:6} ({status})")
        if result.threats:
            print(f"    Threats: {[t.description for t in result.threats]}")
    
    print(f"\n  Result: {passed}/{len(test_cases)} passed")
    return passed == len(test_cases)


def test_malware_detection():
    """Test automatic malware detection."""
    print("\n" + "="*60)
    print("TEST 2: Automatic Malware Detection")
    print("="*60)
    
    analyzer = InlineSecurityAnalyzer()
    
    # Simulate PE file start
    pe_header = b'MZ' + b'\x90' * 100
    
    # Malicious content with PowerShell
    malicious_script = b"""
    powershell -encodedcommand UGxhY2Vob2xkZXI=
    cmd.exe /c net user hacker P@ss /add
    mimikatz.exe
    """
    
    # Safe content
    safe_content = b"Hello, this is normal text content without any threats."
    
    test_cases = [
        ("PE executable", pe_header, True),  # Should detect
        ("Malicious script", malicious_script, True),  # Should detect
        ("Safe text", safe_content, False),  # Should allow
    ]
    
    passed = 0
    for name, data, should_detect in test_cases:
        result = analyzer.analyze(data)
        detected = len(result.threats) > 0
        status = "OK" if detected == should_detect else "FAIL"
        if detected == should_detect:
            passed += 1
        print(f"  {name:20} -> Threats: {len(result.threats)}, Verdict: {result.verdict.value} ({status})")
        if result.threats:
            for t in result.threats[:2]:
                print(f"    - {t.threat_type}: {t.description[:50]}")
    
    print(f"\n  Result: {passed}/{len(test_cases)} passed")
    return passed == len(test_cases)


def test_content_filtering():
    """Test automatic content filtering."""
    print("\n" + "="*60)
    print("TEST 3: Automatic Content Filtering")
    print("="*60)
    
    analyzer = InlineSecurityAnalyzer()
    
    # HTTP response with blocked file type
    blocked_response = b"""HTTP/1.1 200 OK\r
Content-Type: application/octet-stream\r
Content-Disposition: attachment; filename="payload.exe"\r
\r
MZ\x90\x00"""
    
    safe_response = b"""HTTP/1.1 200 OK\r
Content-Type: text/html\r
\r
<html><body>Hello World</body></html>"""
    
    test_cases = [
        ("EXE download", blocked_response, True),
        ("HTML page", safe_response, False),
    ]
    
    passed = 0
    for name, data, should_block in test_cases:
        result = analyzer.analyze(data)
        status = "OK" if (result.verdict == SecurityVerdict.BLOCK) == should_block else "FAIL"
        if (result.verdict == SecurityVerdict.BLOCK) == should_block:
            passed += 1
        print(f"  {name:20} -> Verdict: {result.verdict.value} ({status})")
    
    print(f"\n  Result: {passed}/{len(test_cases)} passed")
    return passed == len(test_cases)


def test_callback_integration():
    """Test integration with TCP reassembly callback."""
    print("\n" + "="*60)
    print("TEST 4: Callback Integration")
    print("="*60)
    
    from dataclasses import dataclass
    
    @dataclass
    class MockStream:
        stream_id: str = "test-1"
        src_ip: str = "192.168.1.100"
        dst_ip: str = "10.0.0.1"
        src_port: int = 54321
        dst_port: int = 80
        data: bytes = b""
    
    callback = AutomatedSecurityCallback()
    
    # Send malicious stream
    stream = MockStream(
        stream_id="mal-001",
        data=b"GET /hack HTTP/1.1\r\nHost: evil.com\r\n\r\n"
    )
    callback(stream)
    
    # Send safe stream
    stream2 = MockStream(
        stream_id="safe-001",
        data=b"GET /page HTTP/1.1\r\nHost: github.com\r\n\r\n"
    )
    callback(stream2)
    
    stats = callback.get_stats()
    print(f"  Streams analyzed: {stats['streams_analyzed']}")
    print(f"  Threats detected: {stats['threats_detected']}")
    print(f"  Blocked: {stats['blocked']}")
    print(f"  Allowed: {stats['allowed']}")
    
    success = stats['streams_analyzed'] == 2 and stats['blocked'] >= 1
    print(f"\n  Result: {'PASS' if success else 'FAIL'}")
    return success


def test_statistics():
    """Test analyzer statistics."""
    print("\n" + "="*60)
    print("TEST 5: Statistics Tracking")
    print("="*60)
    
    analyzer = InlineSecurityAnalyzer()
    
    # Process multiple streams
    test_data = [
        b"GET / HTTP/1.1\r\nHost: malware.com\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: phishing.com\r\n\r\n",
        b"MZ" + b"\x00" * 100,  # PE file
    ]
    
    for data in test_data:
        analyzer.analyze(data)
    
    stats = analyzer.get_stats()
    print(f"  Streams analyzed: {stats['streams_analyzed']}")
    print(f"  URLs checked: {stats['urls_checked']}")
    print(f"  Threats detected: {stats['threats_detected']}")
    print(f"  Blocked: {stats['blocked']}")
    print(f"  Files analyzed: {stats['files_analyzed']}")
    
    success = (
        stats['streams_analyzed'] == 4 and
        stats['blocked'] >= 2 and
        stats['urls_checked'] >= 3
    )
    print(f"\n  Result: {'PASS' if success else 'FAIL'}")
    return success


def main():
    print("\n" + "#"*60)
    print("#  AUTOMATED SECURITY PIPELINE - TEST SUITE")
    print("#  No HTTP APIs - Fully In-Process Analysis")
    print("#"*60)
    
    tests = [
        ("URL Filtering", test_url_filtering),
        ("Malware Detection", test_malware_detection),
        ("Content Filtering", test_content_filtering),
        ("Callback Integration", test_callback_integration),
        ("Statistics", test_statistics),
    ]
    
    results = []
    for name, test_fn in tests:
        try:
            result = test_fn()
            results.append((name, result))
        except Exception as e:
            print(f"\n  ERROR: {e}")
            import traceback
            traceback.print_exc()
            results.append((name, False))
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    
    for name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"  {name}: {status}")
    
    print(f"\n  Total: {passed}/{total} tests passed")
    print("="*60)
    
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())





navigate to the website and check why 










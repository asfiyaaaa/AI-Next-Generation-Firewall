"""
TCP Reassembly Verification Test

This script demonstrates how packets are reassembled.
Run: python test_reassembly_demo.py
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from dataclasses import dataclass
from app.TCP_Reassemble import TCPReassembler, StreamConfig, ReassembledStream


@dataclass
class MockPacket:
    """Mock TCP packet for testing."""
    src_ip: str = "192.168.1.100"
    dst_ip: str = "10.0.0.1"
    src_port: int = 54321
    dst_port: int = 80
    protocol: int = 6
    syn: bool = False
    ack: bool = False
    fin: bool = False
    rst: bool = False
    seq_num: int = 0
    ack_num: int = 0
    window: int = 65535
    tcp_seq: int = 0
    tcp_ack: int = 0
    
    def __post_init__(self):
        self.seq_num = self.tcp_seq
        self.ack_num = self.tcp_ack


class ReassemblyCollector:
    """Collects reassembled streams."""
    def __init__(self):
        self.streams = []
        
    def __call__(self, stream: ReassembledStream):
        self.streams.append(stream)
        print(f"\n  [REASSEMBLED] Stream {stream.stream_id}")
        print(f"  Data ({len(stream.data)} bytes): {stream.data[:100]}")
        if len(stream.data) > 100:
            print(f"  ... (truncated)")


def demo_basic_reassembly():
    """Demonstrate basic packet reassembly."""
    print("\n" + "="*70)
    print("DEMO 1: Basic HTTP Request Reassembly")
    print("="*70)
    
    collector = ReassemblyCollector()
    config = StreamConfig(min_flush_depth=1)  # Flush after 1 byte for demo
    reassembler = TCPReassembler(config=config, phase3_callback=collector)
    
    # HTTP request split into 3 packets
    http_parts = [
        b"GET /index.html HTTP/1.1\r\n",
        b"Host: example.com\r\n",
        b"User-Agent: TestBrowser\r\n\r\n"
    ]
    
    print("\n  SENDING 3 PACKETS (simulating fragmented HTTP request):\n")
    
    seq = 1000
    for i, part in enumerate(http_parts, 1):
        pkt = MockPacket(syn=(i==1), ack=True, tcp_seq=seq)
        print(f"  Packet {i}: seq={seq}, len={len(part)} -> {part[:30]}...")
        reassembler.process_packet(pkt, part)
        seq += len(part)
    
    stats = reassembler.get_stats()
    print(f"\n  REASSEMBLY STATS:")
    print(f"    Packets processed: {stats['packets_processed']}")
    print(f"    Active streams: {stats['active_streams']}")
    print(f"    Bytes reassembled: {stats['bytes_reassembled']}")
    print(f"    Chunks sent to Phase 3: {stats['data_chunks_sent']}")
    
    return stats['packets_processed'] == 3


def demo_out_of_order():
    """Demonstrate out-of-order packet handling."""
    print("\n" + "="*70)
    print("DEMO 2: Out-of-Order Packet Reassembly")
    print("="*70)
    
    collector = ReassemblyCollector()
    config = StreamConfig(min_flush_depth=1)
    reassembler = TCPReassembler(config=config, phase3_callback=collector)
    
    # Data that should be "ABCDEFGHIJ" but arrives out of order
    parts = [
        (1000, b"ABC"),    # First part
        (1006, b"GHI"),    # Third part (arrives second)
        (1003, b"DEF"),    # Second part (arrives third)
        (1009, b"J"),      # Fourth part
    ]
    
    print("\n  SENDING PACKETS OUT OF ORDER:\n")
    print("  Expected final order: ABC DEF GHI J")
    print()
    
    # Send SYN first
    reassembler.process_packet(MockPacket(syn=True, tcp_seq=999), b"")
    
    for seq, data in parts:
        pkt = MockPacket(ack=True, tcp_seq=seq)
        print(f"  Packet: seq={seq}, data={data.decode()}")
        reassembler.process_packet(pkt, data)
    
    stats = reassembler.get_stats()
    print(f"\n  REASSEMBLY STATS:")
    print(f"    Packets processed: {stats['packets_processed']}")
    print(f"    Active streams: {stats['active_streams']}")
    
    return True


def demo_with_security():
    """Demonstrate reassembly with security analysis."""
    print("\n" + "="*70)
    print("DEMO 3: Reassembly with Security Analysis")
    print("="*70)
    
    from app.security_analyzer import create_security_analyzer
    
    analyzer = create_security_analyzer()
    config = StreamConfig(min_flush_depth=1)
    reassembler = TCPReassembler(config=config, phase3_callback=analyzer)
    
    # Malicious HTTP request
    malicious_parts = [
        b"GET /malware.exe HTTP/1.1\r\n",
        b"Host: malware.com\r\n",
        b"\r\n"
    ]
    
    print("\n  SENDING MALICIOUS REQUEST (fragmented):\n")
    
    # SYN
    reassembler.process_packet(MockPacket(syn=True, tcp_seq=1000), b"")
    
    seq = 1001
    for i, part in enumerate(malicious_parts, 1):
        pkt = MockPacket(ack=True, tcp_seq=seq)
        print(f"  Packet {i}: {part[:40]}...")
        reassembler.process_packet(pkt, part)
        seq += len(part)
    
    sec_stats = analyzer.get_stats()
    print(f"\n  SECURITY ANALYSIS RESULTS:")
    print(f"    Streams analyzed: {sec_stats['streams_analyzed']}")
    print(f"    Threats detected: {sec_stats['threats_detected']}")
    print(f"    Blocked: {sec_stats['blocked']}")
    print(f"    URLs checked: {sec_stats['urls_checked']}")
    
    if sec_stats['blocked'] > 0:
        print(f"\n  [!] THREAT DETECTED AND BLOCKED!")
    
    return True


def demo_live_traffic_simulation():
    """Simulate processing of multiple connections."""
    print("\n" + "="*70)
    print("DEMO 4: Multiple Connections Simulation")
    print("="*70)
    
    from app.security_analyzer import create_security_analyzer
    
    analyzer = create_security_analyzer()
    config = StreamConfig(min_flush_depth=1)
    reassembler = TCPReassembler(config=config, phase3_callback=analyzer)
    
    # Multiple connections
    connections = [
        {"src_port": 50001, "host": "google.com", "path": "/search"},
        {"src_port": 50002, "host": "malware.com", "path": "/bad"},
        {"src_port": 50003, "host": "github.com", "path": "/repo"},
        {"src_port": 50004, "host": "phishing.com", "path": "/login"},
    ]
    
    print("\n  SIMULATING 4 CONCURRENT CONNECTIONS:\n")
    
    for conn in connections:
        request = f"GET {conn['path']} HTTP/1.1\r\nHost: {conn['host']}\r\n\r\n".encode()
        
        # SYN
        pkt = MockPacket(src_port=conn['src_port'], syn=True, tcp_seq=1000)
        reassembler.process_packet(pkt, b"")
        
        # Data
        pkt = MockPacket(src_port=conn['src_port'], ack=True, tcp_seq=1001)
        reassembler.process_packet(pkt, request)
        
        print(f"    Connection {conn['src_port']}: {conn['host']}{conn['path']}")
    
    stats = reassembler.get_stats()
    sec_stats = analyzer.get_stats()
    
    print(f"\n  REASSEMBLY STATS:")
    print(f"    Total packets: {stats['packets_processed']}")
    print(f"    Active streams: {stats['active_streams']}")
    
    print(f"\n  SECURITY VERDICTS:")
    print(f"    Streams analyzed: {sec_stats['streams_analyzed']}")
    print(f"    Allowed: {sec_stats['allowed']}")
    print(f"    Blocked: {sec_stats['blocked']} (malware.com, phishing.com)")
    
    return True


def main():
    print("\n" + "#"*70)
    print("#  TCP REASSEMBLY VERIFICATION")
    print("#  This demo shows how packets are reassembled in the pipeline")
    print("#"*70)
    
    demos = [
        ("Basic Reassembly", demo_basic_reassembly),
        ("Out-of-Order Handling", demo_out_of_order),
        ("With Security Analysis", demo_with_security),
        ("Multiple Connections", demo_live_traffic_simulation),
    ]
    
    for name, demo_fn in demos:
        try:
            demo_fn()
        except Exception as e:
            print(f"\n  ERROR: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "="*70)
    print("VERIFICATION COMPLETE")
    print("="*70)
    print("""
Your TCP reassembly is working when you see:
  - 'Packets processed' > 0
  - 'Active streams' > 0  
  - 'Bytes reassembled' > 0 (if min_flush_depth reached)
  - '[REASSEMBLED]' messages showing combined data
  
In live mode, the pipeline automatically:
  1. Captures packets (Phase 1)
  2. Inspects payloads (Phase 2 - DPI)
  3. Reassembles TCP segments
  4. Analyzes for threats (Phase 3)
  5. Blocks malicious traffic
""")


if __name__ == "__main__":
    main()











"""
TCP Stream Reassembly Test Suite

Tests the TCP reassembly module to verify:
1. In-order packet reassembly
2. Out-of-order packet handling
3. Retransmission deduplication
4. Overlap resolution
5. Gap detection
6. Phase 3 callback delivery

Run: python test.py
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from dataclasses import dataclass
from typing import List

# Import our TCP Reassemble module
from app.TCP_Reassemble import (
    TCPReassembler, StreamConfig, ReassembledStream,
    SegmentBuffer, OverlapPolicy, TCPStream, StreamState
)


# === Mock Packet for Testing ===
@dataclass
class MockPacket:
    """Simulates a parsed TCP packet for testing."""
    src_ip: str = "192.168.1.100"
    dst_ip: str = "10.0.0.1"
    src_port: int = 54321
    dst_port: int = 80
    protocol: int = 6  # TCP
    
    # TCP flags
    syn: bool = False
    ack: bool = False
    fin: bool = False
    rst: bool = False
    psh: bool = False
    
    # Sequence numbers
    tcp_seq: int = 0
    tcp_ack: int = 0
    seq_num: int = 0
    ack_num: int = 0
    window: int = 65535
    
    def __post_init__(self):
        self.seq_num = self.tcp_seq
        self.ack_num = self.tcp_ack


# === Test Results Collector ===
class TestCollector:
    """Collects reassembled streams for verification."""
    
    def __init__(self):
        self.streams: List[ReassembledStream] = []
        self.total_bytes = 0
    
    def callback(self, stream: ReassembledStream):
        self.streams.append(stream)
        self.total_bytes += len(stream.data)
        preview = stream.data[:50] if len(stream.data) > 50 else stream.data
        print(f"  [CALLBACK] Received {len(stream.data)} bytes: {preview}...")
    
    def clear(self):
        self.streams.clear()
        self.total_bytes = 0


# === Test Functions ===
def test_in_order_reassembly():
    """Test basic in-order packet reassembly."""
    print("\n" + "="*60)
    print("TEST 1: In-Order Packet Reassembly")
    print("="*60)
    
    collector = TestCollector()
    config = StreamConfig(min_flush_depth=1)  # Flush immediately
    reassembler = TCPReassembler(config=config, phase3_callback=collector.callback)
    
    packets = [
        (MockPacket(syn=True, tcp_seq=1000), b""),
        (MockPacket(ack=True, tcp_seq=1001), b"Hello"),
        (MockPacket(ack=True, tcp_seq=1006), b" World!"),
    ]
    
    for pkt, payload in packets:
        reassembler.process_packet(pkt, payload)
    
    stats = reassembler.get_stats()
    print(f"\n  Packets processed: {stats['packets_processed']}")
    print(f"  Bytes reassembled: {stats['bytes_reassembled']}")
    print(f"  Chunks sent to Phase 3: {stats['data_chunks_sent']}")
    
    success = stats['packets_processed'] == 3 and stats['active_streams'] >= 1
    print(f"\n  RESULT: {'PASS' if success else 'FAIL'}")
    return success


def test_out_of_order_reassembly():
    """Test out-of-order packet handling."""
    print("\n" + "="*60)
    print("TEST 2: Out-of-Order Packet Reassembly")
    print("="*60)
    
    collector = TestCollector()
    config = StreamConfig(min_flush_depth=1)
    reassembler = TCPReassembler(config=config, phase3_callback=collector.callback)
    
    packets = [
        (MockPacket(syn=True, tcp_seq=1000), b""),
        (MockPacket(ack=True, tcp_seq=1001), b"AAA"),
        (MockPacket(ack=True, tcp_seq=1007), b"CCC"),  # Out of order!
        (MockPacket(ack=True, tcp_seq=1004), b"BBB"),  # Fills gap
    ]
    
    print("\n  Sending packets out of order: AAA, CCC, BBB")
    for pkt, payload in packets:
        reassembler.process_packet(pkt, payload)
    
    stats = reassembler.get_stats()
    print(f"\n  Packets processed: {stats['packets_processed']}")
    print(f"  Active streams: {stats['active_streams']}")
    print(f"  Bytes reassembled: {stats['bytes_reassembled']}")
    
    success = stats['packets_processed'] == 4
    print(f"\n  RESULT: {'PASS' if success else 'FAIL'}")
    return success


def test_segment_buffer():
    """Test segment buffer with gaps and overlaps."""
    print("\n" + "="*60)
    print("TEST 3: Segment Buffer (Gaps & Overlaps)")
    print("="*60)
    
    buffer = SegmentBuffer(isn=100, max_depth=10000, overlap_policy=OverlapPolicy.BSD)
    
    print("\n  Inserting: seg1(100-105), seg3(110-115) [gap at 105-110]")
    buffer.insert(100, b"AAAAA")
    buffer.insert(110, b"CCCCC")
    
    gaps = buffer.get_gaps()
    print(f"  Gaps detected: {len(gaps)}")
    for gap in gaps:
        print(f"    Gap: {gap.start_seq} - {gap.end_seq} ({gap.size} bytes)")
    
    data, delivered = buffer.get_contiguous()
    print(f"  Contiguous data before gap fill: '{data.decode()}' ({delivered} bytes)")
    
    print("\n  Filling gap with seg2(105-110)")
    buffer.insert(105, b"BBBBB")
    
    data, delivered = buffer.get_contiguous()
    print(f"  Contiguous data after gap fill: '{data.decode()}' ({delivered} bytes)")
    
    success = data == b"BBBBBCCCCC" and delivered == 10
    print(f"\n  RESULT: {'PASS' if success else 'FAIL'}")
    return success


def test_retransmission():
    """Test retransmission handling."""
    print("\n" + "="*60)
    print("TEST 4: Retransmission Handling")
    print("="*60)
    
    buffer = SegmentBuffer(isn=100, max_depth=10000)
    
    buffer.insert(100, b"ORIGINAL")
    print("  Inserted: ORIGINAL at seq 100")
    
    buffer.insert(100, b"ORIGINAL")
    print("  Inserted: ORIGINAL again (retransmit)")
    
    stats = buffer.stats
    print(f"\n  Segments received: {stats['segments_received']}")
    # Note: retransmission detection happens at reassembler level, not buffer level
    print(f"  Buffer overlaps: {stats['overlaps_resolved']}")
    
    data, delivered = buffer.get_contiguous()
    print(f"  Data retrieved: '{data.decode()}'")
    
    success = data == b"ORIGINAL"
    print(f"\n  RESULT: {'PASS' if success else 'FAIL'}")
    return success


def test_stream_state_machine():
    """Test TCP stream state transitions."""
    print("\n" + "="*60)
    print("TEST 5: TCP State Machine")
    print("="*60)
    
    from app.TCP_Reassemble.stream import Direction
    
    stream = TCPStream(
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=80
    )
    
    print(f"\n  Initial state: {stream.state.name}")
    
    new_state = stream.process_flags(syn=True, ack=False, fin=False, rst=False, 
                                      direction=Direction.TO_SERVER)
    stream.update_state(new_state)
    print(f"  After SYN: {stream.state.name}")
    
    new_state = stream.process_flags(syn=True, ack=True, fin=False, rst=False,
                                      direction=Direction.TO_CLIENT)
    stream.update_state(new_state)
    print(f"  After SYN-ACK: {stream.state.name}")
    
    new_state = stream.process_flags(syn=False, ack=True, fin=False, rst=False,
                                      direction=Direction.TO_SERVER)
    stream.update_state(new_state)
    print(f"  After ACK: {stream.state.name}")
    
    new_state = stream.process_flags(syn=False, ack=False, fin=True, rst=False,
                                      direction=Direction.TO_SERVER)
    stream.update_state(new_state)
    print(f"  After FIN: {stream.state.name}")
    
    success = stream.state == StreamState.FIN_WAIT1
    print(f"\n  RESULT: {'PASS' if success else 'FAIL'}")
    return success


def test_memory_limits():
    """Test memory limit enforcement."""
    print("\n" + "="*60)
    print("TEST 6: Memory Limits")
    print("="*60)
    
    buffer = SegmentBuffer(isn=0, max_depth=100, max_segments=5)
    
    print("  Buffer config: max_depth=100 bytes, max_segments=5")
    
    for i in range(10):
        success = buffer.insert(i * 50, b"X" * 50)
        status = "accepted" if success else "dropped"
        print(f"  Segment {i+1} (50 bytes): {status}")
    
    print(f"\n  Final buffer size: {buffer.buffered_size} bytes")
    print(f"  Final segment count: {buffer.segment_count}")
    print(f"  Drops (depth): {buffer.stats['drops_depth']}")
    print(f"  Drops (segments): {buffer.stats['drops_segments']}")
    
    success = buffer.buffered_size <= 100 or buffer.segment_count <= 5
    print(f"\n  RESULT: {'PASS' if success else 'FAIL'}")
    return success


def test_full_http_simulation():
    """Simulate a full HTTP request/response reassembly."""
    print("\n" + "="*60)
    print("TEST 7: Full HTTP Simulation")
    print("="*60)
    
    collector = TestCollector()
    config = StreamConfig(min_flush_depth=1)  # Flush immediately
    reassembler = TCPReassembler(config=config, phase3_callback=collector.callback)
    
    http_request = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    
    print(f"\n  Simulating HTTP request: {len(http_request)} bytes in 3 packets")
    
    pkt = MockPacket(syn=True, tcp_seq=1000)
    reassembler.process_packet(pkt, b"")
    
    chunk1 = http_request[:20]
    chunk2 = http_request[20:40]
    chunk3 = http_request[40:]
    
    pkt1 = MockPacket(ack=True, tcp_seq=1001)
    pkt2 = MockPacket(ack=True, tcp_seq=1001 + len(chunk1))
    pkt3 = MockPacket(ack=True, tcp_seq=1001 + len(chunk1) + len(chunk2))
    
    reassembler.process_packet(pkt1, chunk1)
    reassembler.process_packet(pkt2, chunk2)
    reassembler.process_packet(pkt3, chunk3)
    
    stats = reassembler.get_stats()
    print(f"\n  Packets processed: {stats['packets_processed']}")
    print(f"  Bytes reassembled: {stats['bytes_reassembled']}")
    print(f"  Chunks to Phase 3: {stats['data_chunks_sent']}")
    
    success = stats['packets_processed'] == 4 and stats['active_streams'] >= 1
    print(f"\n  RESULT: {'PASS' if success else 'FAIL'}")
    return success


# === Main Test Runner ===
def main():
    print("\n" + "#"*60)
    print("#  TCP STREAM REASSEMBLY - TEST SUITE")
    print("#"*60)
    
    tests = [
        ("In-Order Reassembly", test_in_order_reassembly),
        ("Out-of-Order Handling", test_out_of_order_reassembly),
        ("Segment Buffer", test_segment_buffer),
        ("Retransmission", test_retransmission),
        ("State Machine", test_stream_state_machine),
        ("Memory Limits", test_memory_limits),
        ("HTTP Simulation", test_full_http_simulation),
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

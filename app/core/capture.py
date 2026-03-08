
import threading
import time
import logging
from typing import Callable, Optional, Dict, Any
from dataclasses import dataclass, field

from .packet_processor import CaptureAction

logger = logging.getLogger(__name__)

@dataclass
class CaptureStats:
    """Packet capture statistics"""
    packets_captured: int = 0
    packets_allowed: int = 0
    packets_dropped: int = 0
    packets_modified: int = 0
    bytes_captured: int = 0
    bytes_allowed: int = 0
    bytes_dropped: int = 0
    errors: int = 0
    start_time: float = field(default_factory=time.time)
    
    @property
    def packets_per_second(self) -> float:
        elapsed = time.time() - self.start_time
        if elapsed > 0:
            return self.packets_captured / elapsed
        return 0.0
    
    @property
    def mbps(self) -> float:
        elapsed = time.time() - self.start_time
        if elapsed > 0:
            return (self.bytes_captured * 8) / (elapsed * 1_000_000)
        return 0.0
    
    def to_dict(self) -> Dict:
        return {
            "packets_captured": self.packets_captured,
            "packets_allowed": self.packets_allowed,
            "packets_dropped": self.packets_dropped,
            "packets_modified": self.packets_modified,
            "bytes_captured": self.bytes_captured,
            "packets_per_second": round(self.packets_per_second, 2),
            "throughput_mbps": round(self.mbps, 2),
            "errors": self.errors,
            "uptime_seconds": round(time.time() - self.start_time, 1)
        }

class WinDivertCapture:
    """
    Windows packet capture using WinDivert.
    """
    
    def __init__(
        self,
        filter_expr: str = "true",
        priority: int = 0,
        layer: str = "network",
        queue_len: int = 4096,
        queue_time: int = 2000
    ):
        self.filter_expr = filter_expr
        self.priority = priority
        self.layer = layer
        self.queue_len = queue_len
        self.queue_time = queue_time
        
        self._handle = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self.stats = CaptureStats()
        
        self._pydivert_available = False
        try:
            import pydivert
            self._pydivert_available = True
            logger.info("WinDivert/pydivert available")
        except ImportError:
            logger.warning("pydivert not installed. Run: pip install pydivert")
    
    def is_available(self) -> bool:
        return self._pydivert_available
    
    def start(
        self,
        callback: Callable[[bytes, bool, Any], tuple],
        blocking: bool = True
    ) -> None:
        """Start packet capture."""
        if not self._pydivert_available:
            raise RuntimeError("pydivert not installed")
        
        import pydivert
        
        with self._lock:
            if self._running:
                return
            self._running = True
            self.stats = CaptureStats()
        
        def capture_loop():
            try:
                logger.info(f"Opening WinDivert: filter='{self.filter_expr}'")
                
                with pydivert.WinDivert(self.filter_expr, priority=self.priority) as w:
                    self._handle = w
                    logger.info("🔥 WinDivert capture started")
                    
                    while self._running:
                        try:
                            packet = w.recv()
                            if packet is None:
                                continue
                            
                            self.stats.packets_captured += 1
                            self.stats.bytes_captured += len(packet.raw)
                            
                            try:
                                action, modified = callback(packet.raw, packet.is_inbound, packet)
                            except Exception as e:
                                logger.error(f"Callback error: {e}")
                                action = CaptureAction.ALLOW
                                modified = None
                                self.stats.errors += 1
                            
                            if action == CaptureAction.DROP:
                                self.stats.packets_dropped += 1
                                self.stats.bytes_dropped += len(packet.raw)
                            elif action == CaptureAction.MODIFY and modified:
                                self.stats.packets_modified += 1
                                packet.raw = modified
                                w.send(packet)
                                self.stats.packets_allowed += 1
                            else:
                                w.send(packet)
                                self.stats.packets_allowed += 1
                                self.stats.bytes_allowed += len(packet.raw)
                        
                        except (OSError, SystemExit) as e:
                            if self._running and "87" not in str(e):
                                logger.error(f"WinDivert error: {e}")
                                self.stats.errors += 1
                            break
            
            except RuntimeError as e:
                # Handle "WinDivert handle is not open" during shutdown
                if "not open" in str(e):
                    logger.debug(f"WinDivert closed during shutdown: {e}")
                else:
                    logger.error(f"WinDivert runtime error: {e}")
                    self.stats.errors += 1
            except Exception as e:
                logger.error(f"WinDivert error: {e}")
                self.stats.errors += 1
            finally:
                self._handle = None
                self._running = False
                logger.info("WinDivert capture stopped")
        
        if blocking:
            capture_loop()
        else:
            self._thread = threading.Thread(target=capture_loop, daemon=True)
            self._thread.start()
    
    def stop(self, timeout: float = 5.0) -> None:
        """Stop packet capture"""
        with self._lock:
            if not self._running:
                return
            self._running = False
            if self._handle:
                try:
                    self._handle.close()
                except:
                    pass
        
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
    
    def get_stats(self) -> Dict:
        return self.stats.to_dict()
    
    def is_running(self) -> bool:
        return self._running


class MockWinDivertCapture(WinDivertCapture):
    """Mock WinDivert capture for testing."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._pydivert_available = True
    
    def start(self, callback: Callable, blocking: bool = True) -> None:
        self._running = True
        self.stats = CaptureStats()
        
        def mock_loop():
            import random
            logger.info("🧪 Mock WinDivert capture started (continuous mode)")
            
            # Realistic IP pools for test traffic
            internal_ips = ["192.168.1.100", "192.168.1.101", "192.168.1.102", "10.0.0.50", "10.0.0.51"]
            external_ips = ["8.8.8.8", "1.1.1.1", "142.250.185.46", "151.101.1.140", "104.16.132.229"]
            common_ports = [80, 443, 53, 8080, 22, 21, 25, 110, 143, 3389]
            
            while self._running:
                time.sleep(random.uniform(0.2, 0.5))  # Variable timing for realism
                
                # Generate random traffic pattern
                is_outbound = random.choice([True, False])
                
                if is_outbound:
                    src_ip = random.choice(internal_ips)
                    dst_ip = random.choice(external_ips)
                    src_port = random.randint(49152, 65535)  # Ephemeral port
                    dst_port = random.choice(common_ports)
                else:
                    src_ip = random.choice(external_ips)
                    dst_ip = random.choice(internal_ips)
                    src_port = random.choice(common_ports)
                    dst_port = random.randint(49152, 65535)
                
                # Randomize TCP flags
                flags = random.choice(["S", "SA", "A", "PA", "FA", "A"])
                
                pkt_data, is_inbound = self.create_mock_tcp(src_ip, src_port, dst_ip, dst_port, flags)
                self.stats.packets_captured += 1
                self.stats.bytes_captured += len(pkt_data)
                
                try:
                    action, _ = callback(pkt_data, is_inbound, None)
                    if action == CaptureAction.DROP:
                        self.stats.packets_dropped += 1
                        self.stats.bytes_dropped += len(pkt_data)
                    else:
                        self.stats.packets_allowed += 1
                        self.stats.bytes_allowed += len(pkt_data)
                except Exception as e:
                    logger.error(f"Mock callback error: {e}")
                    self.stats.errors += 1
                    
            logger.info("Mock capture stopped")
        
        if blocking:
            mock_loop()
        else:
            self._thread = threading.Thread(target=mock_loop, daemon=True)
            self._thread.start()
    
    def create_mock_tcp(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, flags: str) -> tuple:
        # Simplified Mock helper
        import struct
        src_bytes = bytes([int(p) for p in src_ip.split('.')])
        dst_bytes = bytes([int(p) for p in dst_ip.split('.')])
        
        ip_header = bytes([0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00]) + src_bytes + dst_bytes
        
        flag_byte = 0
        if 'S' in flags: flag_byte |= 0x02
        if 'A' in flags: flag_byte |= 0x10
        
        tcp_header = struct.pack(">HHLLBBHHH", src_port, dst_port, 0, 0, 0x50, flag_byte, 65535, 0, 0)
        return ip_header + tcp_header, dst_ip.startswith("192.168")

# Aliases for backward compatibility
PacketCapture = WinDivertCapture
MockPacketCapture = MockWinDivertCapture
CAPTURE_BACKEND = "WinDivert"

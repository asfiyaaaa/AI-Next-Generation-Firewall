"""
WebSocket Manager for Live Packet Streaming

Uses a thread-safe queue to receive packets from the pipeline process
and broadcast them to all connected WebSocket clients.
"""

import asyncio
import json
import logging
import threading
from queue import Queue, Empty
from typing import List, Dict, Any
from datetime import datetime
from fastapi import WebSocket

logger = logging.getLogger(__name__)

# Thread-safe queue for cross-process communication
_packet_queue: Queue = Queue()


class ConnectionManager:
    """Manages active WebSocket connections for live packet streaming."""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._broadcaster_task = None
    
    async def connect(self, websocket: WebSocket):
        """Accept a new WebSocket connection."""
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Total: {len(self.active_connections)}")
        
        # Start the broadcaster if not running
        if self._broadcaster_task is None or self._broadcaster_task.done():
            self._broadcaster_task = asyncio.create_task(self._queue_broadcaster())
    
    async def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"WebSocket client disconnected. Total: {len(self.active_connections)}")
    
    async def broadcast(self, data: Dict[str, Any]):
        """Broadcast packet data to all connected clients."""
        if not self.active_connections:
            return
        
        message = json.dumps(data)
        disconnected = []
        
        for connection in list(self.active_connections):
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.debug(f"Failed to send to client: {e}")
                disconnected.append(connection)
        
        # Clean up disconnected clients
        for conn in disconnected:
            await self.disconnect(conn)
    
    async def _queue_broadcaster(self):
        """Background task that reads from the queue and broadcasts."""
        while True:
            try:
                # Check the queue every 100ms
                await asyncio.sleep(0.1)
                
                # Process all available packets in the queue
                packets_sent = 0
                while not _packet_queue.empty() and packets_sent < 50:
                    try:
                        packet = _packet_queue.get_nowait()
                        await self.broadcast(packet)
                        packets_sent += 1
                    except Empty:
                        break
                        
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Broadcaster error: {e}")


# Global instance
packet_stream_manager = ConnectionManager()


def broadcast_packet(packet_info: Dict[str, Any]):
    """
    Queue a packet for broadcast to all connected WebSocket clients.
    This is thread-safe and can be called from any context.
    
    Expected packet_info format:
    {
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": "TCP",
        "size": 1024,
        "verdict": "ALLOW" | "BLOCK",
        "threat_type": "None" | "Ransomware" | "BotNet" etc.
    }
    """
    packet_info["timestamp"] = datetime.now().isoformat()
    _packet_queue.put(packet_info)

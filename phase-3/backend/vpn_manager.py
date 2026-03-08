"""
VPN Manager Module - IPsec and SSL VPN Configuration

Provides VPN configuration management, connection status monitoring,
and client configuration generation.
"""

import os
import json
import secrets
import logging
import psutil
import socket
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from enum import Enum

logger = logging.getLogger(__name__)


class VPNProtocol(str, Enum):
    """VPN protocol types."""
    IPSEC = "ipsec"
    SSL_VPN = "ssl_vpn"
    OPENVPN = "openvpn"
    WIREGUARD = "wireguard"


class ConnectionStatus(str, Enum):
    """VPN connection status."""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    ERROR = "error"



class VPNManager:
    """
    VPN Manager for Cyber Crime Department.
    Provides real-time monitoring of actual system VPN interfaces and network traffic.
    """
    
    def __init__(self):
        # Real-time state tracking
        self._last_io_counters = psutil.net_io_counters(pernic=True)
        self._last_io_time = datetime.now()
        
        # Metadata storage for investigation tracking
        self.profiles: Dict[str, Dict[str, Any]] = {}

    def create_profile(self, name: str, protocol: str, username: str, **kwargs) -> Dict[str, Any]:
        """Track a new investigation profile (metadata only)."""
        profile_id = f"VPNP-{secrets.token_hex(4).upper()}"
        profile = {
            "id": profile_id,
            "name": name,
            "protocol": protocol,
            "username": username,
            "created_at": datetime.now().isoformat(),
            "status": "Inactive",
            **kwargs
        }
        self.profiles[profile_id] = profile
        return profile
        
    def get_real_interfaces(self) -> List[Dict[str, Any]]:
        """Get list of real network interfaces and their current status."""
        interfaces = []
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            io_counters = psutil.net_io_counters(pernic=True)
            
            for name, addr_list in addrs.items():
                if_stats = stats.get(name)
                if_io = io_counters.get(name)
                
                ipv4 = next((a.address for a in addr_list if a.family == socket.AF_INET), "None")
                
                # Identify if it's likely a VPN interface (common VPN naming patterns)
                is_vpn = any(prefix in name.lower() for prefix in ['tun', 'tap', 'ppp', 'wg', 'ipsec', 'vboxnet', 'tailscale', 'zerotier'])
                
                interfaces.append({
                    "name": name,
                    "is_up": if_stats.isup if if_stats else False,
                    "speed": if_stats.speed if if_stats else 0,
                    "mtu": if_stats.mtu if if_stats else 0,
                    "ipv4": ipv4,
                    "is_vpn": is_vpn,
                    "bytes_sent": if_io.bytes_sent if if_io else 0,
                    "bytes_recv": if_io.bytes_recv if if_io else 0,
                    "packets_sent": if_io.packets_sent if if_io else 0,
                    "packets_recv": if_io.packets_recv if if_io else 0
                })
        except Exception as e:
            logger.error(f"Error getting interfaces: {e}")
        return interfaces

    def get_live_bandwidth(self) -> Dict[str, Any]:
        """Calculate real-time bandwidth usage (Kbps)."""
        now = datetime.now()
        current_io = psutil.net_io_counters(pernic=True)
        elapsed = (now - self._last_io_time).total_seconds()
        
        if elapsed <= 0:
            return {"download": 0, "upload": 0, "total": 0}
            
        total_sent = 0
        total_recv = 0
        
        for name, io in current_io.items():
            if name in self._last_io_counters:
                last_io = self._last_io_counters[name]
                total_sent += (io.bytes_sent - last_io.bytes_sent)
                total_recv += (io.bytes_recv - last_io.bytes_recv)
                
        # Update markers
        self._last_io_counters = current_io
        self._last_io_time = now
        
        # Convert to Kbps
        kbps_up = (total_sent * 8) / (1024 * elapsed)
        kbps_down = (total_recv * 8) / (1024 * elapsed)
        
        return {
            "download": round(kbps_down, 2),
            "upload": round(kbps_up, 2),
            "total": round(kbps_down + kbps_up, 2),
            "timestamp": now.strftime("%H:%M:%S")
        }

    def get_active_system_connections(self, vpn_only: bool = True) -> List[Dict[str, Any]]:
        """Get list of real active network connections."""
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                # Filter for established connections
                if conn.status != psutil.CONN_ESTABLISHED:
                    continue
                
                # Try to map PID to process name
                process_name = "Unknown"
                if conn.pid:
                    try:
                        process_name = psutil.Process(conn.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                # If vpn_only is True, we try to filter for common VPN ports/processes
                # In a real forensic tool, we'd look for VPN-related processes
                vpn_keywords = ['vpn', 'openvpn', 'wireguard', 'tailscale', 'zerotier', 'forticlient']
                is_vpn_related = any(kw in process_name.lower() for kw in vpn_keywords)
                
                if vpn_only and not is_vpn_related:
                    continue

                connections.append({
                    "fd": conn.fd,
                    "family": "IPv4" if conn.family == socket.AF_INET else "IPv6",
                    "type": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                    "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                    "status": conn.status,
                    "pid": conn.pid,
                    "process": process_name,
                    "is_vpn": is_vpn_related
                })
        except Exception as e:
            logger.error(f"Error getting connections: {e}")
        return connections

    def list_profiles(self) -> List[Any]:
        """List tracked investigation profiles."""
        return list(self.profiles.values())

    def delete_profile(self, profile_id: str) -> bool:
        """Remove an investigation profile."""
        if profile_id in self.profiles:
            del self.profiles[profile_id]
            return True
        return False

    def get_statistics(self) -> Dict[str, Any]:
        """Get REAL system network and VPN statistics."""
        interfaces = self.get_real_interfaces()
        vpn_interfaces = [i for i in interfaces if i['is_vpn'] and i['is_up']]
        
        # Calculate total system traffic
        io_total = psutil.net_io_counters()
        
        return {
            "active_vpn_tunnels": len(vpn_interfaces),
            "total_interfaces": len(interfaces),
            "system_bytes_sent": io_total.bytes_sent,
            "system_bytes_recv": io_total.bytes_recv,
            "vpn_interfaces": [i['name'] for i in vpn_interfaces],
            "status": "Operational"
        }


# Global instance
vpn_manager = VPNManager()


def create_vpn_profile(name: str, protocol: str, username: str, **kwargs):
    """Create and track an investigation profile."""
    return vpn_manager.create_profile(name, protocol, username, **kwargs)


def get_vpn_status() -> Dict[str, Any]:
    """Get REAL VPN server status and statistics."""
    return vpn_manager.get_statistics()


def list_active_connections() -> List[Dict[str, Any]]:
    """List active system network connections (detected in real-time)."""
    return vpn_manager.get_active_system_connections(vpn_only=True)


def export_client_config(profile_id: str, format: str = "openvpn") -> Optional[str]:
    """Stub for client configuration export."""
    return f"# Zero-Simulation Mode: Actual system VPN configuration should be managed via OS tools.\n# Profile ID: {profile_id}\n# Format: {format}"


def get_real_interfaces() -> List[Dict[str, Any]]:
    """Get list of real system network interfaces."""
    return vpn_manager.get_real_interfaces()


def get_live_bandwidth() -> Dict[str, Any]:
    """Get real-time bandwidth statistics."""
    return vpn_manager.get_live_bandwidth()


def list_system_connections(vpn_only: bool = True) -> List[Dict[str, Any]]:
    """List active system network connections."""
    return vpn_manager.get_active_system_connections(vpn_only=vpn_only)

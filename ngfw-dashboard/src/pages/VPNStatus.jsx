import React, { useState, useEffect } from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { apiClient } from '../api/client';
import './VPNStatus.css';

const VPNStatus = () => {
    const [interfaces, setInterfaces] = useState([]);
    const [connections, setConnections] = useState([]);
    const [bandwidthData, setBandwidthData] = useState([]);
    const [isLoading, setIsLoading] = useState(true);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const [ifaceData, connData, bwData] = await Promise.all([
                    apiClient.get('/api/system/interfaces'),
                    apiClient.get('/api/system/connections'),
                    apiClient.get('/api/system/bandwidth')
                ]);

                setInterfaces(ifaceData || []);
                setConnections(connData || []);

                // Maintain a rolling history of bandwidth data
                setBandwidthData(prev => {
                    const newPoint = {
                        time: bwData.timestamp,
                        upload: bwData.upload,
                        download: bwData.download
                    };
                    const updated = [...prev, newPoint];
                    if (updated.length > 20) return updated.slice(1);
                    return updated;
                });

                setIsLoading(false);
            } catch (error) {
                console.error("Failed to fetch VPN status", error);
            }
        };

        fetchData();
        const interval = setInterval(fetchData, 3000);
        return () => clearInterval(interval);
    }, []);

    if (isLoading && interfaces.length === 0) {
        return <div className="page-content">Connecting to platform interfaces...</div>;
    }

    return (
        <div className="vpn-status-page fade-in">
            <div className="vpn-header">
                <h1>Network & VPN Status</h1>
                <p>Monitor real-time network interface activity and active VPN tunnels.</p>
            </div>

            <div className="vpn-grid">
                <div className="interfaces-section card">
                    <h3>Network Interfaces</h3>
                    <div className="interface-list">
                        {interfaces.map(iface => (
                            <div key={iface.name} className={`interface-item ${iface.is_up ? 'up' : 'down'}`}>
                                <div className="iface-main">
                                    <span className="iface-icon">{iface.is_vpn ? '🛡️' : '🔌'}</span>
                                    <div className="iface-info">
                                        <span className="iface-name">{iface.name}</span>
                                        <span className="iface-ip">{iface.ipv4}</span>
                                    </div>
                                </div>
                                <div className="iface-status">
                                    <span className="status-label">{iface.is_up ? 'Up' : 'Down'}</span>
                                    <span className="speed-label">{iface.speed > 0 ? `${iface.speed} Mbps` : 'Auto'}</span>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                <div className="bandwidth-section card">
                    <h3>Live Bandwidth (Kbps)</h3>
                    <div className="chart-body">
                        <ResponsiveContainer width="100%" height={250}>
                            <AreaChart data={bandwidthData}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#30363d" vertical={false} />
                                <XAxis dataKey="time" stroke="#8b949e" tick={{ fontSize: 10 }} />
                                <YAxis stroke="#8b949e" tick={{ fontSize: 10 }} />
                                <Tooltip
                                    contentStyle={{ backgroundColor: '#161b22', border: '1px solid #30363d', borderRadius: '8px' }}
                                />
                                <Area type="monotone" dataKey="download" stroke="#58a6ff" fill="#58a6ff" fillOpacity={0.1} animationDuration={300} />
                                <Area type="monotone" dataKey="upload" stroke="#bc8cff" fill="#bc8cff" fillOpacity={0.1} animationDuration={300} />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                    <div className="bandwidth-legend">
                        <span className="legend-item"><span className="dot blue"></span> Download</span>
                        <span className="legend-item"><span className="dot purple"></span> Upload</span>
                    </div>
                </div>
            </div>

            <div className="connections-section card">
                <div className="section-header">
                    <h3>System Network Connections</h3>
                    <span className="conn-count">{connections.length} Active Streams Detected</span>
                </div>
                <div className="table-wrapper">
                    <table className="connections-table">
                        <thead>
                            <tr>
                                <th>Process</th>
                                <th>Protocol</th>
                                <th>Local Address</th>
                                <th>Remote Address</th>
                                <th>Status</th>
                                <th>Type</th>
                            </tr>
                        </thead>
                        <tbody>
                            {connections.length > 0 ? connections.map((conn, idx) => (
                                <tr key={idx}>
                                    <td className="user-cell">
                                        <div className="user-avatar-sm">{conn.process.charAt(0).toUpperCase()}</div>
                                        {conn.process}
                                    </td>
                                    <td className="mono">{conn.family}</td>
                                    <td className="mono">{conn.local_addr}</td>
                                    <td className="mono">{conn.remote_addr}</td>
                                    <td><span className={`status-tag ${conn.status.toLowerCase()}`}>{conn.status}</span></td>
                                    <td><span className="protocol-tag">{conn.type}</span></td>
                                </tr>
                            )) : (
                                <tr>
                                    <td colSpan="6" style={{ textAlign: 'center', padding: '2rem' }}>No active VPN-related connections found.</td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
};

export default VPNStatus;

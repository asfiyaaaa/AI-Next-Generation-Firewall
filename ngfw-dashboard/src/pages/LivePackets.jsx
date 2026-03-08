import React, { useState, useEffect, useRef } from 'react';
import './LivePackets.css';

const LivePackets = () => {
    const [packets, setPackets] = useState([]);
    const [isConnected, setIsConnected] = useState(false);
    const [connectionError, setConnectionError] = useState(null);
    const containerRef = useRef(null);
    const wsRef = useRef(null);

    useEffect(() => {
        const connectWebSocket = () => {
            const ws = new WebSocket('ws://localhost:8000/ws/live-packets');
            wsRef.current = ws;

            ws.onopen = () => {
                setIsConnected(true);
                setConnectionError(null);
                console.log('Live packet stream connected');
            };

            ws.onmessage = (event) => {
                try {
                    const packet = JSON.parse(event.data);
                    setPackets(prev => {
                        const updated = [...prev, packet];
                        // Keep only the last 200 packets to avoid memory issues
                        if (updated.length > 200) return updated.slice(-200);
                        return updated;
                    });
                } catch (e) {
                    console.error('Failed to parse packet:', e);
                }
            };

            ws.onclose = () => {
                setIsConnected(false);
                console.log('WebSocket closed, reconnecting in 3s...');
                setTimeout(connectWebSocket, 3000);
            };

            ws.onerror = (error) => {
                setConnectionError('Failed to connect to live packet stream');
                console.error('WebSocket error:', error);
            };
        };

        connectWebSocket();

        return () => {
            if (wsRef.current) {
                wsRef.current.close();
            }
        };
    }, []);

    // Auto-scroll to bottom when new packets arrive
    useEffect(() => {
        if (containerRef.current) {
            containerRef.current.scrollTop = containerRef.current.scrollHeight;
        }
    }, [packets]);

    const stats = {
        total: packets.length,
        allowed: packets.filter(p => p.verdict === 'ALLOW').length,
        blocked: packets.filter(p => p.verdict === 'BLOCK').length
    };

    return (
        <div className="live-packets-page fade-in">
            <div className="packets-header">
                <div>
                    <h1>📡 Live Packet Stream</h1>
                    <p>Real-time network traffic analysis and security verdicts.</p>
                </div>
                <div className={`connection-status ${isConnected ? 'connected' : 'disconnected'}`}>
                    <span className="status-dot"></span>
                    {isConnected ? 'Connected' : 'Reconnecting...'}
                </div>
            </div>

            <div className="packets-stats-row">
                <div className="stat-box card">
                    <span className="stat-label">Total Packets</span>
                    <span className="stat-value">{stats.total}</span>
                </div>
                <div className="stat-box card allowed">
                    <span className="stat-label">Allowed</span>
                    <span className="stat-value text-green">{stats.allowed}</span>
                </div>
                <div className="stat-box card blocked">
                    <span className="stat-label">Blocked</span>
                    <span className="stat-value text-red">{stats.blocked}</span>
                </div>
            </div>

            {connectionError && (
                <div className="error-banner">{connectionError}</div>
            )}

            <div className="packets-feed card" ref={containerRef}>
                <table className="packets-table">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Source</th>
                            <th>Destination</th>
                            <th>Protocol</th>
                            <th>Size</th>
                            <th>Verdict</th>
                            <th>Threat</th>
                        </tr>
                    </thead>
                    <tbody>
                        {packets.length === 0 ? (
                            <tr>
                                <td colSpan="7" className="empty-message">
                                    Waiting for packets... Ensure the NGFW pipeline is running.
                                </td>
                            </tr>
                        ) : (
                            packets.map((pkt, idx) => (
                                <tr key={idx} className={`packet-row ${pkt.verdict.toLowerCase()}`}>
                                    <td className="mono time-col">
                                        {new Date(pkt.timestamp).toLocaleTimeString()}
                                    </td>
                                    <td className="mono">{pkt.src_ip}:{pkt.src_port}</td>
                                    <td className="mono">{pkt.dst_ip}:{pkt.dst_port}</td>
                                    <td>{pkt.protocol}</td>
                                    <td>{pkt.size} B</td>
                                    <td>
                                        <span className={`verdict-badge ${pkt.verdict.toLowerCase()}`}>
                                            {pkt.verdict}
                                        </span>
                                    </td>
                                    <td className="threat-col">
                                        {pkt.threat_type !== 'None' ? (
                                            <span className="threat-tag">{pkt.threat_type}</span>
                                        ) : (
                                            <span className="safe-tag">Clean</span>
                                        )}
                                    </td>
                                </tr>
                            ))
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

export default LivePackets;

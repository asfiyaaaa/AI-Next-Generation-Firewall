import React, { useState, useEffect } from 'react';
import { apiClient } from '../api/client';
import ThreatTable from '../components/ThreatTable';
import './ThreatMonitor.css';

const ThreatMonitor = () => {
    const [threats, setThreats] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [filter, setFilter] = useState('all');

    const fetchThreats = async () => {
        try {
            const data = await apiClient.get('/api/dashboard/stats');

            const formattedThreats = (data.recent || []).map(t => {
                let analyses = [];
                try {
                    analyses = typeof t.analyses === 'string' ? JSON.parse(t.analyses || '[]') : (t.analyses || []);
                } catch (e) {
                    console.error("Parse error for analyses", e);
                }

                return {
                    timestamp: t.analyzed_at,
                    source_ip: t.src_ip,
                    destination: t.dst_ip,
                    type: (analyses && analyses[0]?.type) || 'Security Scan',
                    severity: (analyses && analyses[0]?.severity) || (t.verdict?.toLowerCase() === 'block' ? 'Critical' : 'Low'),
                    action: t.verdict ? (t.verdict.charAt(0).toUpperCase() + t.verdict.slice(1)) : 'Unknown',
                    data_size: t.data_size
                };
            });

            setThreats(formattedThreats);
            // Sync count from backend if available
            if (data.streams) setTotalLogsFromBackend(data.streams);
            setIsLoading(false);
        } catch (error) {
            console.error("Failed to fetch threat logs", error);
        }
    };

    const [totalLogsFromBackend, setTotalLogsFromBackend] = useState(0);
    const [liveLogCount, setLiveLogCount] = useState(0);

    useEffect(() => {
        fetchThreats();
        // Removed 5s interval to prevent overwriting live WebSocket data

        // WebSocket for real-time updates
        const wsUrl = `ws://${window.location.hostname}:8000/ws/live-packets`;
        const ws = new WebSocket(wsUrl);

        ws.onmessage = (event) => {
            try {
                const packet = JSON.parse(event.data);
                const newThreat = {
                    timestamp: packet.timestamp || new Date().toISOString(),
                    source_ip: packet.src_ip,
                    destination: packet.dst_ip,
                    type: packet.threat_type || 'Security Scan',
                    severity: packet.verdict?.toLowerCase() === 'block' ? 'Critical' : 'Low',
                    action: packet.verdict ? (packet.verdict.charAt(0).toUpperCase() + packet.verdict.slice(1).toLowerCase()) : 'Unknown',
                    data_size: packet.size
                };

                setThreats(prev => [newThreat, ...prev].slice(0, 100)); // Keep last 100
                setLiveLogCount(prev => prev + 1);
            } catch (err) {
                console.error("WS Message handling error", err);
            }
        };

        return () => {
            ws.close();
        };
    }, []);

    const filteredThreats = threats.filter(t => {
        if (filter === 'all') return true;
        const actionLower = (t.action || '').toLowerCase();
        if (filter === 'blocked') return actionLower === 'block' || actionLower === 'blocked' || actionLower === 'dropped';
        if (filter === 'allowed') return actionLower === 'allow' || actionLower === 'allowed' || actionLower === 'passed';
        return true;
    });

    if (isLoading) return <div className="page-content">Loading threat monitor...</div>;

    return (
        <div className="threat-monitor-page fade-in">
            <div className="monitor-header">
                <div>
                    <h1>Threat Monitor</h1>
                    <p>Real-time security events and traffic analysis logs.</p>
                </div>
                <div className="filter-controls">
                    <button
                        className={`filter-btn ${filter === 'all' ? 'active' : ''}`}
                        onClick={() => setFilter('all')}
                    >All Events</button>
                    <button
                        className={`filter-btn ${filter === 'blocked' ? 'active' : ''}`}
                        onClick={() => setFilter('blocked')}
                    >Blocked</button>
                    <button
                        className={`filter-btn ${filter === 'allowed' ? 'active' : ''}`}
                        onClick={() => setFilter('allowed')}
                    >Allowed</button>
                </div>
            </div>

            <div className="threat-stats-row">
                <div className="mini-stat card">
                    <span className="mini-stat-label">Critical Threats</span>
                    <span className="mini-stat-value text-red">{threats.filter(t => t.severity === 'Critical').length}</span>
                </div>
                <div className="mini-stat card">
                    <span className="mini-stat-label">High Severity</span>
                    <span className="mini-stat-value text-orange">{threats.filter(t => t.severity === 'High').length}</span>
                </div>
                <div className="mini-stat card">
                    <span className="mini-stat-label">Total Logs</span>
                    <span className="mini-stat-value">{totalLogsFromBackend + liveLogCount}</span>
                </div>
            </div>

            <div className="monitor-table-container card">
                <ThreatTable threats={filteredThreats} />
            </div>
        </div>
    );
};

export default ThreatMonitor;

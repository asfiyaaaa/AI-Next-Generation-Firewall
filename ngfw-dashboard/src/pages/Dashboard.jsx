import React, { useState, useEffect } from 'react';
import StatCard from '../components/StatCard';
import {
    LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid,
    Tooltip, ResponsiveContainer, BarChart, Bar, Cell
} from 'recharts';
import { apiClient } from '../api/client';
import ThreatTable from '../components/ThreatTable';
import './Dashboard.css';

const Dashboard = () => {
    const [stats, setStats] = useState({
        packets: 0,
        threats: 0,
        activeStreams: 0,
        blockedUrls: 0
    });
    const [recentThreats, setRecentThreats] = useState([]);
    const [trafficData, setTrafficData] = useState([]);
    const [categoryData, setCategoryData] = useState([]);
    const [isLoading, setIsLoading] = useState(true);

    useEffect(() => {
        const fetchStats = async () => {
            try {
                const data = await apiClient.get('/api/dashboard/stats');
                setStats({
                    packets: data.packets,
                    threats: data.threats,
                    activeStreams: data.streams,
                    blockedUrls: data.blocked_urls
                });

                // Format recent threats from backend
                const formattedThreats = (data.recent || []).map(t => {
                    let analyses = [];
                    try {
                        analyses = typeof t.analyses === 'string' ? JSON.parse(t.analyses || '[]') : (t.analyses || []);
                    } catch (e) {
                        console.error("Parse error", e);
                    }

                    return {
                        timestamp: t.analyzed_at,
                        source_ip: t.src_ip,
                        destination: t.dst_ip,
                        type: (analyses && analyses[0]?.type) || 'Security Scan',
                        severity: (analyses && analyses[0]?.severity) || 'Medium',
                        action: t.verdict ? (t.verdict.charAt(0).toUpperCase() + t.verdict.slice(1)) : 'Unknown'
                    };
                });

                setRecentThreats(formattedThreats);
                setTrafficData(data.traffic);
                setCategoryData(data.categories);
                setIsLoading(false);
            } catch (error) {
                console.error("Failed to fetch dashboard stats", error);
            }
        };


        fetchStats();
        // Removed 5s interval to prevent overwriting live WebSocket data

        // WebSocket for real-time updates
        const wsUrl = `ws://${window.location.hostname}:8000/ws/live-packets`;
        const ws = new WebSocket(wsUrl);

        ws.onmessage = (event) => {
            try {
                const packet = JSON.parse(event.data);

                // Update stats incrementally
                setStats(prev => ({
                    ...prev,
                    packets: prev.packets + 1,
                    activeStreams: prev.activeStreams + 1,
                    threats: packet.verdict?.toLowerCase() === 'block' ? prev.threats + 1 : prev.threats
                }));

                // Update recent threats
                const newThreat = {
                    timestamp: packet.timestamp || new Date().toISOString(),
                    source_ip: packet.src_ip,
                    destination: packet.dst_ip,
                    type: packet.threat_type || 'Security Scan',
                    severity: packet.verdict?.toLowerCase() === 'block' ? 'Critical' : 'Low',
                    action: packet.verdict ? (packet.verdict.charAt(0).toUpperCase() + packet.verdict.slice(1).toLowerCase()) : 'Unknown'
                };
                setRecentThreats(prev => [newThreat, ...prev].slice(0, 10));

            } catch (err) {
                console.error("WS error", err);
            }
        };

        return () => {
            ws.close();
        };
    }, []);

    if (isLoading) return <div className="page-content">Loading security dashboard...</div>;

    return (
        <div className="dashboard-page fade-in">
            <div className="stats-grid">
                <StatCard
                    title="Total Packets"
                    value={stats.packets.toLocaleString()}
                    icon="📦"
                    color="blue"
                />
                <StatCard
                    title="Threats Blocked"
                    value={stats.threats}
                    icon="🛡️"
                    color="red"
                />
                <StatCard
                    title="Active Streams"
                    value={stats.activeStreams.toLocaleString()}
                    icon="🌊"
                    color="green"
                />
                <StatCard
                    title="Blocked URLs"
                    value={stats.blockedUrls}
                    icon="🌐"
                    color="yellow"
                />
            </div>

            <div className="charts-grid">
                <div className="chart-container card">
                    <div className="chart-header">
                        <h3>Traffic Analysis</h3>
                        <div className="chart-legend">
                            <span className="legend-item"><span className="dot blue"></span> Packets</span>
                            <span className="legend-item"><span className="dot red"></span> Threats</span>
                        </div>
                    </div>
                    <div className="chart-body">
                        <ResponsiveContainer width="100%" height={300}>
                            <AreaChart data={trafficData}>
                                <defs>
                                    <linearGradient id="colorPackets" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="#58a6ff" stopOpacity={0.3} />
                                        <stop offset="95%" stopColor="#58a6ff" stopOpacity={0} />
                                    </linearGradient>
                                </defs>
                                <CartesianGrid strokeDasharray="3 3" stroke="#30363d" vertical={false} />
                                <XAxis dataKey="time" stroke="#8b949e" tick={{ fontSize: 12 }} />
                                <YAxis stroke="#8b949e" tick={{ fontSize: 12 }} />
                                <Tooltip
                                    contentStyle={{ backgroundColor: '#161b22', border: '1px solid #30363d', borderRadius: '8px' }}
                                    itemStyle={{ fontSize: '12px' }}
                                />
                                <Area type="monotone" dataKey="packets" stroke="#58a6ff" fillOpacity={1} fill="url(#colorPackets)" />
                                <Line type="monotone" dataKey="threats" stroke="#f85149" strokeWidth={2} dot={false} />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                <div className="chart-container card">
                    <div className="chart-header">
                        <h3>Threat Categories</h3>
                    </div>
                    <div className="chart-body">
                        <ResponsiveContainer width="100%" height={300}>
                            <BarChart data={categoryData} layout="vertical" margin={{ left: 20 }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#30363d" horizontal={false} />
                                <XAxis type="number" hide />
                                <YAxis dataKey="name" type="category" stroke="#8b949e" tick={{ fontSize: 12 }} width={80} />
                                <Tooltip
                                    cursor={{ fill: 'transparent' }}
                                    contentStyle={{ backgroundColor: '#161b22', border: '1px solid #30363d', borderRadius: '8px' }}
                                />
                                <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={20}>
                                    {categoryData.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={entry.color} />
                                    ))}
                                </Bar>
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            </div>

            <div className="recent-threats-section card">
                <div className="section-header">
                    <h3>Recent Security Events</h3>
                    <button className="view-all-btn">View All Logs</button>
                </div>
                <ThreatTable threats={recentThreats} />
            </div>
        </div>
    );
};

export default Dashboard;

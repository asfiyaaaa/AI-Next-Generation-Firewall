import React, { createContext, useContext, useState, useEffect, useRef } from 'react';

const NotificationContext = createContext();

export const NotificationProvider = ({ children }) => {
    const [notifications, setNotifications] = useState([]);
    const [unreadCount, setUnreadCount] = useState(0);
    const wsRef = useRef(null);

    useEffect(() => {
        const connectWebSocket = () => {
            const ws = new WebSocket('ws://localhost:8000/ws/live-packets');
            wsRef.current = ws;

            ws.onopen = () => {
                console.log('Notification stream connected');
            };

            ws.onmessage = (event) => {
                try {
                    const packet = JSON.parse(event.data);

                    // Only notify for blocked packets or detected threats
                    if (packet.verdict === 'BLOCK' || (packet.threat_type && packet.threat_type !== 'None')) {
                        const newNotification = {
                            id: Date.now(),
                            timestamp: packet.timestamp || new Date().toISOString(),
                            type: packet.verdict === 'BLOCK' ? 'block' : 'threat',
                            title: packet.threat_type !== 'None' ? `Threat Detected: ${packet.threat_type}` : 'Packet Blocked',
                            message: `${packet.protocol} packet from ${packet.src_ip} to ${packet.dst_ip} was ${packet.verdict.toLowerCase()}.`,
                            read: false,
                            severity: packet.threat_type !== 'None' ? 'high' : 'medium'
                        };

                        setNotifications(prev => [newNotification, ...prev].slice(0, 50));
                        setUnreadCount(prev => prev + 1);
                    }
                } catch (e) {
                    console.error('Failed to parse notification packet:', e);
                }
            };

            ws.onclose = () => {
                console.log('Notification stream closed, reconnecting...');
                setTimeout(connectWebSocket, 5000);
            };

            ws.onerror = (error) => {
                console.error('Notification WebSocket error:', error);
            };
        };

        connectWebSocket();

        return () => {
            if (wsRef.current) {
                wsRef.current.close();
            }
        };
    }, []);

    const markAsRead = (id) => {
        setNotifications(prev => prev.map(n => n.id === id ? { ...n, read: true } : n));
        setUnreadCount(prev => Math.max(0, prev - 1));
    };

    const markAllAsRead = () => {
        setNotifications(prev => prev.map(n => ({ ...n, read: true })));
        setUnreadCount(0);
    };

    const clearNotifications = () => {
        setNotifications([]);
        setUnreadCount(0);
    };

    return (
        <NotificationContext.Provider value={{
            notifications,
            unreadCount,
            markAsRead,
            markAllAsRead,
            clearNotifications
        }}>
            {children}
        </NotificationContext.Provider>
    );
};

export const useNotifications = () => {
    const context = useContext(NotificationContext);
    if (!context) {
        throw new Error('useNotifications must be used within a NotificationProvider');
    }
    return context;
};

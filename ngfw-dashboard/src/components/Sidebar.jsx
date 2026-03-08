import React, { useState, useEffect } from 'react';
import { NavLink } from 'react-router-dom';
import { apiClient } from '../api/client';
import { useAuth } from '../context/AuthContext';
import './Sidebar.css';

const Sidebar = () => {
    const [isOnline, setIsOnline] = useState(false);
    const { isAdmin } = useAuth();

    useEffect(() => {
        const checkStatus = async () => {
            try {
                await apiClient.get('/health');
                setIsOnline(true);
            } catch (error) {
                setIsOnline(false);
            }
        };

        checkStatus();
        const interval = setInterval(checkStatus, 5000);
        return () => clearInterval(interval);
    }, []);

    const menuItems = [
        { name: 'Dashboard', path: '/', icon: '📊', roles: ['guest', 'user', 'analyst', 'security-admin', 'admin'] },
        { name: 'Live Packets', path: '/live-packets', icon: '📡', roles: ['user', 'analyst', 'security-admin', 'admin'] },
        { name: 'Threat Monitor', path: '/threat-monitor', icon: '🛡️', roles: ['user', 'analyst', 'security-admin', 'admin'] },
        { name: 'URL Filter', path: '/url-filter', icon: '🌐', roles: ['analyst', 'security-admin', 'admin'] },
        { name: 'Malware Scanner', path: '/malware-scanner', icon: '🦠', roles: ['analyst', 'security-admin', 'admin'] },
        { name: 'VPN Status', path: '/vpn-status', icon: '🔒', roles: ['security-admin', 'admin'] },
        { name: 'User Management', path: '/users', icon: '👥', roles: ['admin'] },
        { name: 'Settings', path: '/settings', icon: '⚙️', roles: ['security-admin', 'admin'] },
    ];

    const { user: currentUser } = useAuth();

    const filteredMenuItems = menuItems.filter(item => {
        if (!currentUser || !currentUser.roles) return false;
        // Normalize roles: convert underscores to hyphens for comparison
        const normalizedUserRoles = currentUser.roles.map(role => role.replace(/_/g, '-'));
        return item.roles.some(role => normalizedUserRoles.includes(role));
    });

    return (
        <aside className="sidebar">
            <div className="sidebar-logo">
                <img src="/assets/company-logo.jpeg" alt="Cogninode Technologies" className="company-logo" />
                <div className="company-info">
                    <h1 className="company-name">COGNINODE TECHNOLOGIES</h1>
                    <p className="product-name">NGFW Firewall</p>
                </div>
            </div>

            <nav className="sidebar-nav">
                <ul>
                    {filteredMenuItems.map((item) => (
                        <li key={item.path}>
                            <NavLink
                                to={item.path}
                                className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}
                            >
                                <span className="nav-icon">{item.icon}</span>
                                <span className="nav-name">{item.name}</span>
                            </NavLink>
                        </li>
                    ))}
                </ul>
            </nav>

            <div className="sidebar-footer">
                <div className="system-status">
                    <div className={`status-dot ${isOnline ? 'online' : 'offline'}`}></div>
                    <span>{isOnline ? 'System Online' : 'System Offline'}</span>
                </div>
            </div>
        </aside>
    );
};

export default Sidebar;

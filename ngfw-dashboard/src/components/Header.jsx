import React, { useState } from 'react';
import { useNotifications } from '../context/NotificationContext';
import { useAuth } from '../context/AuthContext';
import './Header.css';

const Header = ({ title }) => {
    const { notifications, unreadCount, markAsRead, clearNotifications } = useNotifications();
    const { user, logout } = useAuth();
    const [showNotifications, setShowNotifications] = useState(false);
    const [showUserMenu, setShowUserMenu] = useState(false);

    return (
        <header className="header glass">
            <div className="header-left">
                <h2>{title}</h2>
            </div>

            <div className="header-right">
                <div className="header-search">
                    <span className="search-icon">🔍</span>
                    <input type="text" placeholder="Search threats, logs..." />
                </div>

                <div className="header-actions">
                    <div className="notifications-wrapper">
                        <button
                            className="action-btn"
                            title="Notifications"
                            onClick={() => setShowNotifications(!showNotifications)}
                        >
                            <span className="icon">🔔</span>
                            {unreadCount > 0 && <span className="badge">{unreadCount}</span>}
                        </button>

                        {showNotifications && (
                            <div className="notifications-dropdown">
                                <div className="dropdown-header">
                                    <h3>Notifications</h3>
                                    <button className="clear-btn" onClick={clearNotifications}>Clear All</button>
                                </div>
                                <div className="notifications-list">
                                    {notifications.length === 0 ? (
                                        <div className="empty-notifications">No new notifications</div>
                                    ) : (
                                        notifications.map(notif => (
                                            <div
                                                key={notif.id}
                                                className={`notification-item ${!notif.read ? 'unread' : ''}`}
                                                onClick={() => markAsRead(notif.id)}
                                            >
                                                <div className={`notif-icon ${notif.type}`}>
                                                    {notif.type === 'block' ? '🚫' : '⚠️'}
                                                </div>
                                                <div className="notif-content">
                                                    <div className="notif-title">{notif.title}</div>
                                                    <div className="notif-msg">{notif.message}</div>
                                                    <span className="notif-time">{new Date(notif.timestamp).toLocaleTimeString()}</span>
                                                </div>
                                            </div>
                                        ))
                                    )}
                                </div>
                            </div>
                        )}
                    </div>

                    <div className="user-profile-wrapper">
                        <div className="user-profile" onClick={() => setShowUserMenu(!showUserMenu)}>
                            <div className="user-avatar">
                                {user?.display_name?.substring(0, 2).toUpperCase() || 'JD'}
                            </div>
                            <div className="user-info">
                                <span className="user-name">{user?.display_name || 'John Doe'}</span>
                                <span className="user-role">{user?.roles?.[0] || 'Security Admin'}</span>
                            </div>
                            <span className="chevron">▼</span>
                        </div>

                        {showUserMenu && (
                            <div className="user-dropdown card">
                                <div className="dropdown-item" onClick={logout}>
                                    <span className="icon">🚪</span> Logout Session
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </header>
    );
};

export default Header;

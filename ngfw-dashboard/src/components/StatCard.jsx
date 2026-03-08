import React from 'react';
import './StatCard.css';

const StatCard = ({ title, value, icon, color = 'blue' }) => {
    return (
        <div className="stat-card card">
            <div className="stat-card-header">
                <div className={`stat-icon icon-${color}`}>{icon}</div>
                <span className="live-indicator">
                    <span className="live-dot"></span>
                    LIVE
                </span>
            </div>
            <div className="stat-card-body">
                <h3 className="stat-title">{title}</h3>
                <p className="stat-value">{value}</p>
            </div>
        </div>
    );
};

export default StatCard;

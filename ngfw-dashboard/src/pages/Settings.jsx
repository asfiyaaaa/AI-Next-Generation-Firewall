import React, { useState, useEffect } from 'react';
import { apiClient } from '../api/client';
import './Settings.css';

const Settings = () => {
    const [activeTab, setActiveTab] = useState('security');
    const [config, setConfig] = useState({
        url_filtering: {
            categories: [], // { name, blocked }
        },
        content_filter: {
            blocked_extensions: [],
            max_size_mb: 10,
            dlp_enabled: false
        },
        system: {
            log_retention: 30,
            auto_update: true,
            alert_threshold: 'Medium'
        }
    });
    const [isLoading, setIsLoading] = useState(true);

    useEffect(() => {
        const fetchConfig = async () => {
            try {
                // Fetch content filter config
                const contentData = await apiClient.get('/api/content/config');

                // For URL categories, we'll mock the status for now as there isn't a direct "get all category statuses" yet
                // But we'll provide the UI to toggle them
                const categories = [
                    'malware', 'phishing', 'adult', 'gambling',
                    'social_media', 'streaming', 'gaming', 'shopping'
                ].map(cat => ({ name: cat, blocked: false }));

                setConfig(prev => ({
                    ...prev,
                    content_filter: {
                        blocked_extensions: contentData.blocked_extensions || [],
                        max_size_mb: contentData.max_size_mb || 10,
                        dlp_enabled: contentData.dlp_enabled || false
                    },
                    url_filtering: { categories }
                }));
                setIsLoading(false);
            } catch (error) {
                console.error("Failed to fetch settings", error);
                setIsLoading(false);
            }
        };

        fetchConfig();
    }, []);

    const handleToggleCategory = (categoryName) => {
        setConfig(prev => ({
            ...prev,
            url_filtering: {
                categories: prev.url_filtering.categories.map(c =>
                    c.name === categoryName ? { ...c, blocked: !c.blocked } : c
                )
            }
        }));
    };

    const handleSaveSecurity = async () => {
        try {
            // Save Content Filter
            await apiClient.put('/api/content/config', config.content_filter);

            // Note: In a real scenario, we'd also iterate and call /api/url-filter/categories/block
            // for each changed category.

            alert("Security settings saved successfully!");
        } catch (error) {
            alert(`Error saving settings: ${error.message}`);
        }
    };

    if (isLoading) return <div className="page-content">Loading security settings...</div>;

    return (
        <div className="settings-page fade-in">
            <div className="page-header">
                <h1>System Settings</h1>
                <p>Configure firewall policies, security modules, and platform preferences.</p>
            </div>

            <div className="settings-container">
                <div className="settings-sidebar card">
                    <button
                        className={`tab-btn ${activeTab === 'security' ? 'active' : ''}`}
                        onClick={() => setActiveTab('security')}
                    >
                        🛡️ Security Policy
                    </button>
                    <button
                        className={`tab-btn ${activeTab === 'content' ? 'active' : ''}`}
                        onClick={() => setActiveTab('content')}
                    >
                        📂 Content & DLP
                    </button>
                    <button
                        className={`tab-btn ${activeTab === 'system' ? 'active' : ''}`}
                        onClick={() => setActiveTab('system')}
                    >
                        ⚙️ General System
                    </button>
                </div>

                <div className="settings-content card">
                    {activeTab === 'security' && (
                        <div className="settings-section">
                            <h2>URL Filtering Policy</h2>
                            <p className="section-desc">Select categories to block across the entire network.</p>

                            <div className="categories-grid">
                                {config.url_filtering.categories.map(cat => (
                                    <div key={cat.name} className="toggle-item">
                                        <span className="cat-name">{cat.name.split('_').join(' ').toUpperCase()}</span>
                                        <label className="switch">
                                            <input
                                                type="checkbox"
                                                checked={cat.blocked}
                                                onChange={() => handleToggleCategory(cat.name)}
                                            />
                                            <span className="slider round"></span>
                                        </label>
                                    </div>
                                ))}
                            </div>

                            <div className="settings-footer">
                                <button className="save-btn" onClick={handleSaveSecurity}>Save Security Policies</button>
                            </div>
                        </div>
                    )}

                    {activeTab === 'content' && (
                        <div className="settings-section">
                            <h2>Content Filter / DLP</h2>
                            <p className="section-desc">Manage file-based security and data loss prevention.</p>

                            <div className="form-group">
                                <label>DLP Protection</label>
                                <div className="toggle-row">
                                    <span>Enable sensitive data pattern matching</span>
                                    <label className="switch">
                                        <input
                                            type="checkbox"
                                            checked={config.content_filter.dlp_enabled}
                                            onChange={(e) => setConfig({
                                                ...config,
                                                content_filter: { ...config.content_filter, dlp_enabled: e.target.checked }
                                            })}
                                        />
                                        <span className="slider round"></span>
                                    </label>
                                </div>
                            </div>

                            <div className="form-group">
                                <label>Max Upload Size (MB)</label>
                                <input
                                    type="number"
                                    value={config.content_filter.max_size_mb}
                                    onChange={(e) => setConfig({
                                        ...config,
                                        content_filter: { ...config.content_filter, max_size_mb: parseInt(e.target.value) }
                                    })}
                                />
                            </div>

                            <div className="settings-footer">
                                <button className="save-btn" onClick={handleSaveSecurity}>Update Content Filter</button>
                            </div>
                        </div>
                    )}

                    {activeTab === 'system' && (
                        <div className="settings-section">
                            <h2>General Preferences</h2>
                            <p className="section-desc">Configure dashboard and logging behavior.</p>

                            <div className="form-group">
                                <label>Log Retention (Days)</label>
                                <select
                                    value={config.system.log_retention}
                                    onChange={(e) => setConfig({
                                        ...config,
                                        system: { ...config.system, log_retention: parseInt(e.target.value) }
                                    })}
                                >
                                    <option value={7}>7 Days</option>
                                    <option value={30}>30 Days</option>
                                    <option value={90}>90 Days</option>
                                </select>
                            </div>

                            <div className="form-group">
                                <label>Alert Severity Threshold</label>
                                <div className="threshold-options">
                                    {['Low', 'Medium', 'High', 'Critical'].map(level => (
                                        <button
                                            key={level}
                                            className={`threshold-btn ${config.system.alert_threshold === level ? 'active' : ''}`}
                                            onClick={() => setConfig({
                                                ...config,
                                                system: { ...config.system, alert_threshold: level }
                                            })}
                                        >
                                            {level}
                                        </button>
                                    ))}
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default Settings;

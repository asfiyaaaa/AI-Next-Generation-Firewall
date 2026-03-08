import React, { useState, useEffect } from 'react';
import { apiClient } from '../api/client';
import './URLFilter.css';

const URLFilter = () => {
    const [urlInput, setUrlInput] = useState('');
    const [blocklist, setBlocklist] = useState([]);
    const [categories, setCategories] = useState([]);
    const [isLoading, setIsLoading] = useState(true);

    const fetchData = async () => {
        try {
            const [listData, catData] = await Promise.all([
                apiClient.get('/api/url/blocklist'),
                apiClient.get('/api/url/categories')
            ]);

            // Format blocklist from { domain: reason } to array
            const formattedList = Object.entries(listData.blocklist || {}).map(([domain, reason]) => ({
                domain,
                reason,
                timestamp: 'Active'
            }));
            setBlocklist(formattedList);

            // Format categories
            const formattedCats = (catData.categories || []).map(cat => ({
                id: cat,
                name: cat.split('_').join(' ').toUpperCase(),
                blocked: (catData.blocked || []).includes(cat)
            }));
            setCategories(formattedCats);
            setIsLoading(false);
        } catch (error) {
            console.error("Failed to fetch filter data", error);
            setIsLoading(false);
        }
    };

    useEffect(() => {
        fetchData();
    }, []);

    const toggleCategory = async (category, currentlyBlocked) => {
        try {
            await apiClient.post('/api/url/category/block', {
                category,
                blocked: !currentlyBlocked
            });
            fetchData();
        } catch (error) {
            alert(`Failed to update category: ${error.message}`);
        }
    };

    const handleAddDomain = async (e) => {
        e.preventDefault();
        if (!urlInput) return;

        try {
            await apiClient.post('/api/url/blocklist/add', {
                domain: urlInput,
                reason: 'Manual Block'
            });
            setUrlInput('');
            fetchData();
        } catch (error) {
            alert(`Failed to block domain: ${error.message}`);
        }
    };

    const removeDomain = async (domain) => {
        try {
            await apiClient.delete(`/api/url/blocklist/${domain}`);
            fetchData();
        } catch (error) {
            alert(`Failed to remove domain: ${error.message}`);
        }
    };

    if (isLoading) return <div className="page-content">Loading URL filter policies...</div>;

    return (
        <div className="url-filter-page fade-in">
            <div className="filter-header">
                <h1>URL Filtering Management</h1>
                <p>Manage blocked domains and category-based filtering policies in real-time.</p>
            </div>

            <div className="filter-grid">
                <div className="category-section card">
                    <h3>Category Filtering</h3>
                    <p className="subtitle">Block entire categories of websites automatically.</p>

                    <div className="category-list">
                        {categories.map(cat => (
                            <div key={cat.id} className="category-item">
                                <div className="category-info">
                                    <span className="category-name">{cat.name}</span>
                                </div>
                                <label className="switch">
                                    <input
                                        type="checkbox"
                                        checked={cat.blocked}
                                        onChange={() => toggleCategory(cat.id, cat.blocked)}
                                    />
                                    <span className="slider round"></span>
                                </label>
                            </div>
                        ))}
                    </div>
                </div>

                <div className="blocklist-section card">
                    <div className="section-header">
                        <h3>Custom Blocklist</h3>
                        <form className="add-domain-form" onSubmit={handleAddDomain}>
                            <input
                                type="text"
                                placeholder="Enter domain (e.g. example.com)"
                                value={urlInput}
                                onChange={(e) => setUrlInput(e.target.value)}
                            />
                            <button type="submit">Block Domain</button>
                        </form>
                    </div>

                    <div className="blocklist-table-wrapper">
                        <table className="blocklist-table">
                            <thead>
                                <tr>
                                    <th>Domain</th>
                                    <th>Reason</th>
                                    <th>Status</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                {blocklist.length > 0 ? blocklist.map((item, index) => (
                                    <tr key={index}>
                                        <td className="mono">{item.domain}</td>
                                        <td><span className="reason-tag">{item.reason}</span></td>
                                        <td><span className="live-tag">Active</span></td>
                                        <td>
                                            <button
                                                className="remove-btn"
                                                onClick={() => removeDomain(item.domain)}
                                                title="Remove from blocklist"
                                            >
                                                🗑️
                                            </button>
                                        </td>
                                    </tr>
                                )) : (
                                    <tr>
                                        <td colSpan="4" style={{ textAlign: 'center', padding: '2rem' }}>No domains in custom blocklist.</td>
                                    </tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default URLFilter;

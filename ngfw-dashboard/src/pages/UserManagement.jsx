import React, { useState, useEffect } from 'react';
import { apiClient } from '../api/client';
import { useAuth } from '../context/AuthContext';
import './UserManagement.css';

const UserManagement = () => {
    const { isAdmin } = useAuth();
    const [users, setUsers] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [showAddModal, setShowAddModal] = useState(false);
    const [showEditModal, setShowEditModal] = useState(false);
    const [showConfirmDelete, setShowConfirmDelete] = useState(false);
    const [userToDelete, setUserToDelete] = useState(null);
    const [editingUser, setEditingUser] = useState(null);
    const [newUser, setNewUser] = useState({
        username: '',
        password: '',
        email: '',
        display_name: '',
        roles: ['analyst']
    });

    const fetchUsers = async () => {
        try {
            const data = await apiClient.get('/api/auth/users');
            setUsers(data.users || []);
            setIsLoading(false);
        } catch (error) {
            console.error("Failed to fetch users", error);
        }
    };

    useEffect(() => {
        fetchUsers();
    }, []);

    const handleCreateUser = async (e) => {
        e.preventDefault();
        try {
            await apiClient.post('/api/auth/users', newUser);
            setShowAddModal(false);
            setNewUser({ username: '', password: '', email: '', display_name: '', roles: ['analyst'] });
            fetchUsers();
        } catch (error) {
            alert(`Error creating user: ${error.message}`);
        }
    };

    const handleEditUser = (user) => {
        setEditingUser({
            username: user.username,
            email: user.email,
            display_name: user.username,
            roles: user.roles || ['analyst']
        });
        setShowEditModal(true);
    };

    const handleUpdateUser = async (e) => {
        e.preventDefault();
        try {
            // Note: Backend may need an update endpoint - for now we'll show a message
            alert('Edit functionality requires backend API endpoint /api/auth/users/{username} PUT method');
            setShowEditModal(false);
            setEditingUser(null);
        } catch (error) {
            alert(`Error updating user: ${error.message}`);
        }
    };

    const handleDeleteClick = (username) => {
        setUserToDelete(username);
        setShowConfirmDelete(true);
    };

    const confirmDelete = async () => {
        if (!userToDelete) return;

        try {
            await apiClient.delete(`/api/auth/users/${userToDelete}`);
            setShowConfirmDelete(false);
            setUserToDelete(null);
            fetchUsers();
        } catch (error) {
            console.error('Delete error:', error);
            alert(`Error deleting user: ${error.message}`);
        }
    };

    const cancelDelete = () => {
        setShowConfirmDelete(false);
        setUserToDelete(null);
    };

    if (!isAdmin()) {
        return (
            <div className="page-content fade-in">
                <div className="card" style={{ textAlign: 'center', padding: '3rem' }}>
                    <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>🔒</div>
                    <h2>Access Restricted</h2>
                    <p style={{ color: 'var(--text-secondary)', marginTop: '1rem' }}>
                        This module requires Administrative clearance.
                    </p>
                </div>
            </div>
        );
    }

    if (isLoading) return <div className="page-content">Loading user management...</div>;

    return (
        <div className="user-management-page fade-in">
            <div className="page-header">
                <div>
                    <h1>User Management</h1>
                    <p>Manage security analysts, administrators, and investigator roles.</p>
                </div>
                <button className="add-user-btn" onClick={() => setShowAddModal(true)}>
                    + Add New User
                </button>
            </div>

            <div className="users-grid">
                {users.map((user) => (
                    <div key={user.username} className="user-card card">
                        <div className="user-card-header">
                            <div className="user-avatar-large">
                                {user.username.substring(0, 2).toUpperCase()}
                            </div>
                            <div className="user-status-indicator online"></div>
                        </div>
                        <div className="user-card-body">
                            <h3>{user.username}</h3>
                            <p className="user-email">{user.email || 'No email provided'}</p>
                            <div className="user-roles">
                                {user.roles.map(role => (
                                    <span key={role} className={`role-tag ${role.toLowerCase()}`}>
                                        {role}
                                    </span>
                                ))}
                            </div>
                        </div>
                        <div className="user-card-footer">
                            <button type="button" className="edit-btn" onClick={() => handleEditUser(user)}>Edit</button>
                            <button type="button" className="delete-btn" onClick={() => handleDeleteClick(user.username)}>
                                Delete
                            </button>
                        </div>
                    </div>
                ))}
            </div>

            {showAddModal && (
                <div className="modal-overlay">
                    <div className="modal card">
                        <h2>Add New Security User</h2>
                        <form onSubmit={handleCreateUser}>
                            <div className="form-group">
                                <label>Username</label>
                                <input
                                    type="text"
                                    value={newUser.username}
                                    onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                                    required
                                />
                            </div>
                            <div className="form-group">
                                <label>Password</label>
                                <input
                                    type="password"
                                    value={newUser.password}
                                    onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                                    required
                                />
                            </div>
                            <div className="form-group">
                                <label>Email</label>
                                <input
                                    type="email"
                                    value={newUser.email}
                                    onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
                                    required
                                />
                            </div>
                            <div className="form-group">
                                <label>Display Name</label>
                                <input
                                    type="text"
                                    value={newUser.display_name}
                                    onChange={(e) => setNewUser({ ...newUser, display_name: e.target.value })}
                                    required
                                />
                            </div>
                            <div className="form-group">
                                <label>Role</label>
                                <select
                                    className="role-select-dropdown"
                                    value={newUser.roles[0]}
                                    onChange={(e) => setNewUser({ ...newUser, roles: [e.target.value] })}
                                    required
                                >
                                    <option value="guest">Guest</option>
                                    <option value="user">User</option>
                                    <option value="analyst">Analyst</option>
                                    <option value="security-admin">Security-admin</option>
                                </select>
                            </div>
                            <div className="modal-actions">
                                <button type="button" className="cancel-btn" onClick={() => setShowAddModal(false)}>Cancel</button>
                                <button type="submit" className="submit-btn">Create User</button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {showEditModal && editingUser && (
                <div className="modal-overlay">
                    <div className="modal card">
                        <h2>Edit Security User</h2>
                        <form onSubmit={handleUpdateUser}>
                            <div className="form-group">
                                <label>Username (Read-only)</label>
                                <input
                                    type="text"
                                    value={editingUser.username}
                                    disabled
                                    style={{ opacity: 0.6, cursor: 'not-allowed' }}
                                />
                            </div>
                            <div className="form-group">
                                <label>Email</label>
                                <input
                                    type="email"
                                    value={editingUser.email}
                                    onChange={(e) => setEditingUser({ ...editingUser, email: e.target.value })}
                                    required
                                />
                            </div>
                            <div className="form-group">
                                <label>Display Name</label>
                                <input
                                    type="text"
                                    value={editingUser.display_name}
                                    onChange={(e) => setEditingUser({ ...editingUser, display_name: e.target.value })}
                                    required
                                />
                            </div>
                            <div className="form-group">
                                <label>Role</label>
                                <select
                                    className="role-select-dropdown"
                                    value={editingUser.roles[0]}
                                    onChange={(e) => setEditingUser({ ...editingUser, roles: [e.target.value] })}
                                    required
                                >
                                    <option value="guest">Guest</option>
                                    <option value="user">User</option>
                                    <option value="analyst">Analyst</option>
                                    <option value="security-admin">Security-admin</option>
                                </select>
                            </div>
                            <div className="modal-actions">
                                <button type="button" className="cancel-btn" onClick={() => { setShowEditModal(false); setEditingUser(null); }}>Cancel</button>
                                <button type="submit" className="submit-btn">Update User</button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {showConfirmDelete && (
                <div className="modal-overlay">
                    <div className="modal card confirm-modal">
                        <div className="confirm-icon">⚠️</div>
                        <h2>Confirm Deletion</h2>
                        <p className="confirm-message">
                            Are you sure you want to delete user <strong>"{userToDelete}"</strong>?
                        </p>
                        <p className="confirm-warning">
                            This action cannot be undone. The user will be permanently removed from the system.
                        </p>
                        <div className="modal-actions">
                            <button type="button" className="cancel-btn" onClick={cancelDelete}>Cancel</button>
                            <button type="button" className="submit-btn danger-btn" onClick={confirmDelete}>Delete User</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default UserManagement;

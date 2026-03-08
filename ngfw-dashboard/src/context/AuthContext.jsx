import React, { createContext, useContext, useState, useEffect } from 'react';
import { apiClient } from '../api/client';

const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);
    const [isInitializing, setIsInitializing] = useState(false);

    const verifySession = async () => {
        const token = localStorage.getItem('auth_token');
        if (!token) {
            setUser(null);
            setLoading(false);
            return;
        }

        try {
            const data = await apiClient.get('/api/auth/verify');
            setUser(data.user);
        } catch (error) {
            console.error("Session verification failed", error);
            localStorage.removeItem('auth_token');
            setUser(null);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        verifySession();
    }, []);

    const login = async (username, password) => {
        try {
            const data = await apiClient.post('/api/auth/login', { username, password });
            localStorage.setItem('auth_token', data.token);
            setUser(data.user);
            setIsInitializing(true);
            return data;
        } catch (error) {
            throw error;
        }
    };

    const logout = async () => {
        try {
            await apiClient.post('/api/auth/logout');
        } catch (error) {
            console.error("Logout error", error);
        } finally {
            localStorage.removeItem('auth_token');
            setUser(null);
        }
    };

    const hasRole = (role) => {
        if (!user || !user.roles) return false;
        // Normalize roles: convert underscores to hyphens
        const normalizedUserRoles = user.roles.map(r => r.replace(/_/g, '-'));
        if (Array.isArray(role)) {
            return role.some(r => normalizedUserRoles.includes(r));
        }
        return normalizedUserRoles.includes(role);
    };

    const isAdmin = () => hasRole('admin');

    const finishInitialization = () => {
        setIsInitializing(false);
    };

    return (
        <AuthContext.Provider value={{
            user,
            loading,
            isInitializing,
            login,
            logout,
            hasRole,
            isAdmin,
            finishInitialization,
            isAuthenticated: !!user
        }}>
            {children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
};

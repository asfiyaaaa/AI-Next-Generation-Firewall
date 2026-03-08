import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const PrivateRoute = ({ children, requiredRole }) => {
    const { isAuthenticated, loading, hasRole } = useAuth();
    const location = useLocation();

    if (loading) {
        return <div className="loading-screen">Verifying identity...</div>;
    }

    if (!isAuthenticated) {
        // Redirect to login but save the current location they were trying to go to
        return <Navigate to="/login" state={{ from: location }} replace />;
    }

    if (requiredRole && !hasRole(requiredRole)) {
        // Redirect to dashboard if they don't have the required role
        return <Navigate to="/" replace />;
    }

    return children;
};

export default PrivateRoute;

import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import './Login.css';

const Login = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [isSubmitting, setIsSubmitting] = useState(false);

    const { login, isAuthenticated, isInitializing } = useAuth();
    const navigate = useNavigate();
    const location = useLocation();

    const from = location.state?.from?.pathname || "/";

    // Handle redirection after authentication and initialization animation
    useEffect(() => {
        if (isAuthenticated && !isInitializing) {
            navigate(from, { replace: true });
        }
    }, [isAuthenticated, isInitializing, navigate, from]);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setIsSubmitting(true);

        try {
            await login(username, password);
            // Redirection is now handled by the useEffect above
        } catch (err) {
            setError(err.message || 'Invalid username or password');
            setIsSubmitting(false);
        }
    };

    return (
        <div className="login-container">
            <div className="gov-header-banner">
                <img src="/assets/company-logo.jpeg" alt="Cogninode" className="banner-logo" />
                <span>COGNINODE TECHNOLOGIES - ENTERPRISE SECURITY SYSTEM</span>
            </div>

            <div className="login-card professional">
                <div className="login-header">
                    <div className="security-icon-3d">
                        <img src="/assets/company-logo.jpeg" alt="Cogninode Technologies" className="login-logo-main" />
                    </div>
                    <h1>COGNINODE TECHNOLOGIES</h1>
                    <p className="sub-title">NGFW Firewall - Secure Access Portal</p>
                </div>

                <form className="login-form" onSubmit={handleSubmit}>
                    {error && <div className="login-error">{error}</div>}

                    <div className="form-group">
                        <label htmlFor="username">Operator Identity (UID)</label>
                        <div className="input-with-icon">
                            <span className="icon">🆔</span>
                            <input
                                type="text"
                                id="username"
                                placeholder="Enter UID"
                                value={username}
                                onChange={(e) => setUsername(e.target.value)}
                                required
                            />
                        </div>
                    </div>

                    <div className="form-group">
                        <label htmlFor="password">Security Credentials</label>
                        <div className="input-with-icon">
                            <span className="icon">🔑</span>
                            <input
                                type="password"
                                id="password"
                                placeholder="••••••••"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                required
                            />
                        </div>
                    </div>

                    <button
                        type="submit"
                        className="login-btn-gov"
                        disabled={isSubmitting}
                    >
                        {isSubmitting ? 'AUTHORIZING...' : 'INITIATE SECURE SESSION'}
                    </button>

                    <div className="login-disclaimer">
                        By logging in, you agree to the <a href="#">Security Protocol Agreement</a>.
                        Unauthorized access is a federal offense under Section 1030.
                    </div>
                </form>
            </div>

            <div className="background-grid"></div>
        </div>
    );
};

export default Login;

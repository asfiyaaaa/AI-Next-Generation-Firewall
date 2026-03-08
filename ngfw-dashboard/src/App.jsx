import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import Dashboard from './pages/Dashboard';
import ThreatMonitor from './pages/ThreatMonitor';
import URLFilter from './pages/URLFilter';
import MalwareScanner from './pages/MalwareScanner';
import VPNStatus from './pages/VPNStatus';
import UserManagement from './pages/UserManagement';
import Settings from './pages/Settings';
import LivePackets from './pages/LivePackets';
import Login from './pages/Login';
import InitializationOverlay from './components/InitializationOverlay';
import { NotificationProvider } from './context/NotificationContext';
import { AuthProvider, useAuth } from './context/AuthContext';
import PrivateRoute from './components/PrivateRoute';
import './App.css';

// Placeholder components for other pages
const PlaceholderPage = ({ title }) => (
  <div className="page-content fade-in">
    <div className="card">
      <h2>{title} Page</h2>
      <p style={{ marginTop: '1rem', color: 'var(--text-secondary)' }}>
        This module is currently being integrated with the Phase-3 security backend.
      </p>
    </div>
  </div>
);

function AppContent() {
  const { isInitializing, finishInitialization } = useAuth();

  if (isInitializing) {
    return <InitializationOverlay onComplete={finishInitialization} />;
  }

  return (
    <NotificationProvider>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/*" element={
          <PrivateRoute>
            <div className="app-container">
              <Sidebar />
              <div className="main-content">
                <Header title="Network Security Dashboard" />
                <main className="content-area">
                  <Routes>
                    <Route path="/" element={
                      <PrivateRoute requiredRole={['guest', 'user', 'analyst', 'security-admin', 'admin']}>
                        <Dashboard />
                      </PrivateRoute>
                    } />
                    <Route path="/threat-monitor" element={
                      <PrivateRoute requiredRole={['user', 'analyst', 'security-admin', 'admin']}>
                        <ThreatMonitor />
                      </PrivateRoute>
                    } />
                    <Route path="/url-filter" element={
                      <PrivateRoute requiredRole={['analyst', 'security-admin', 'admin']}>
                        <URLFilter />
                      </PrivateRoute>
                    } />
                    <Route path="/malware-scanner" element={
                      <PrivateRoute requiredRole={['analyst', 'security-admin', 'admin']}>
                        <MalwareScanner />
                      </PrivateRoute>
                    } />
                    <Route path="/vpn-status" element={
                      <PrivateRoute requiredRole={['security-admin', 'admin']}>
                        <VPNStatus />
                      </PrivateRoute>
                    } />
                    <Route path="/users" element={
                      <PrivateRoute requiredRole="admin">
                        <UserManagement />
                      </PrivateRoute>
                    } />
                    <Route path="/settings" element={
                      <PrivateRoute requiredRole={['security-admin', 'admin']}>
                        <Settings />
                      </PrivateRoute>
                    } />
                    <Route path="/live-packets" element={
                      <PrivateRoute requiredRole={['user', 'analyst', 'security-admin', 'admin']}>
                        <LivePackets />
                      </PrivateRoute>
                    } />
                  </Routes>
                </main>
              </div>
            </div>
          </PrivateRoute>
        } />
      </Routes>
    </NotificationProvider>
  );
}

function App() {
  return (
    <Router>
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </Router>
  );
}
export default App;

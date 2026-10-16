import React, { useEffect, useState } from 'react';
import { Header } from './components/Header';
import { Footer } from './components/Footer';
import { LandingPage } from './components/LandingPage';
import { HomePage } from './components/HomePage';
import { MessageAnalyzer } from './components/MessageAnalyzer';
import { URLAnalyzer } from './components/URLAnalyzer';
import { QRScanner } from './components/QRScanner';
import { LoginPage } from './components/LoginPage';
import { SignupPage } from './components/SignupPage';
import {
  API_BASE_URL,
  getStoredToken,
  getStoredUser,
  fetchCurrentUser,
  logoutUser,
  type AuthUser,
} from './api';
import type { HealthResponse } from './types/api';

export const App: React.FC = () => {
  const [currentHash, setCurrentHash] = useState<string>(
    window.location.hash || '#/'
  );
  const [backendStatus, setBackendStatus] = useState<'connected' | 'offline' | 'checking'>('checking');
  const [healthData, setHealthData] = useState<HealthResponse | null>(null);
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(getStoredUser());

  // 1. Listen to hash changes for browser forward/back & direct URL navigation
  useEffect(() => {
    const handleHashChange = () => {
      setCurrentHash(window.location.hash || '#/');
    };

    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

  // 2. Validate stored auth session on startup
  useEffect(() => {
    const token = getStoredToken();
    if (token) {
      fetchCurrentUser(token).then((user) => {
        if (user) {
          setCurrentUser(user);
        } else {
          setCurrentUser(null);
        }
      });
    }
  }, []);

  // 3. Health check telemetry
  useEffect(() => {
    const checkHealth = async () => {
      try {
        const res = await fetch(`${API_BASE_URL}/health`);
        if (res.ok) {
          const data: HealthResponse = await res.json();
          setBackendStatus('connected');
          setHealthData(data);
        } else {
          setBackendStatus('offline');
        }
      } catch {
        setBackendStatus('offline');
      }
    };

    checkHealth();
    const interval = setInterval(checkHealth, 10000);
    return () => clearInterval(interval);
  }, []);

  // 4. Navigation helper
  const navigateTo = (path: string) => {
    const targetHash = path === '' || path === '/' ? '#/' : `#/${path.replace(/^#?\/?/, '')}`;
    if (window.location.hash !== targetHash) {
      window.location.hash = targetHash;
    }
    setCurrentHash(targetHash);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleLoginSuccess = (user: AuthUser) => {
    setCurrentUser(user);
  };

  const handleLogout = async () => {
    await logoutUser();
    setCurrentUser(null);
    navigateTo('');
  };

  // Route parsing
  const rawRoute = currentHash.replace(/^#\/?/, '');
  const [path, queryString] = rawRoute.split('?');
  const cleanRoute = (path || '').toLowerCase();
  const queryParams = new URLSearchParams(queryString || '');
  const redirectParam = queryParams.get('redirect') || '';
  const initialEmail = queryParams.get('email') || '';

  const isPublicRoute = cleanRoute === '' || cleanRoute === 'login' || cleanRoute === 'signup';

  // 5. Authentication Route Guard:
  // If user is NOT authenticated and attempts to access protected routes, redirect to login
  useEffect(() => {
    if (!currentUser && !isPublicRoute) {
      navigateTo(`login?redirect=${encodeURIComponent(cleanRoute)}`);
    }
  }, [currentUser, isPublicRoute, cleanRoute]);

  // If user is already authenticated and visits login or signup, redirect back
  useEffect(() => {
    if (currentUser && (cleanRoute === 'login' || cleanRoute === 'signup')) {
      navigateTo(redirectParam ? redirectParam : '');
    }
  }, [currentUser, cleanRoute, redirectParam]);

  // ==========================================
  // UNCONNECTED / PUBLIC VISITOR EXPERIENCE
  // ==========================================
  if (!currentUser) {
    if (cleanRoute === 'login') {
      return (
        <LoginPage
          onNavigate={navigateTo}
          onLoginSuccess={handleLoginSuccess}
          redirectRoute={redirectParam}
        />
      );
    }

    if (cleanRoute === 'signup') {
      return (
        <SignupPage
          onNavigate={navigateTo}
          onLoginSuccess={handleLoginSuccess}
          redirectRoute={redirectParam}
          initialEmail={initialEmail}
        />
      );
    }

    // Default Public View: Full-Screen Edge-to-Edge Hero ONLY!
    // No Header, No Footer, No outer margin wrappers.
    return <LandingPage onNavigate={navigateTo} />;
  }

  // ==========================================
  // AUTHENTICATED USER EXPERIENCE
  // ==========================================
  const getAuthenticatedView = () => {
    if (cleanRoute.startsWith('message')) {
      return <MessageAnalyzer onBackToOverview={() => navigateTo('')} />;
    }
    if (cleanRoute.startsWith('url')) {
      return <URLAnalyzer onBackToOverview={() => navigateTo('')} />;
    }
    if (cleanRoute.startsWith('qr')) {
      return <QRScanner onBackToOverview={() => navigateTo('')} />;
    }

    // Default: Dashboard Overview
    return (
      <HomePage
        onNavigate={navigateTo}
        healthData={healthData}
        backendStatus={backendStatus}
      />
    );
  };

  return (
    <div className="relative min-h-screen text-charcoal flex flex-col font-sans selection:bg-sage-200 selection:text-sage-900 bg-page">
      <div className="relative z-10 flex flex-col min-h-screen">
        <Header
          currentRoute={currentHash}
          onNavigate={navigateTo}
          currentUser={currentUser}
          onLogout={handleLogout}
          backendStatus={backendStatus}
        />

        <main className="flex-grow w-full flex flex-col">
          {getAuthenticatedView()}
        </main>

        <Footer onNavigate={navigateTo} />
      </div>
    </div>
  );
};

export default App;

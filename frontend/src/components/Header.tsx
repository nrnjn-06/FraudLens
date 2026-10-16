import React, { useState } from 'react';
import {
  ShieldCheck,
  MessageSquareText,
  Globe,
  QrCode,
  UserPlus,
  LogOut,
  Menu,
  X,
} from 'lucide-react';
import type { AuthUser } from '../api';

interface HeaderProps {
  currentRoute: string;
  onNavigate: (route: string) => void;
  currentUser: AuthUser | null;
  onLogout: () => void;
  backendStatus: 'connected' | 'offline' | 'checking';
}

export const Header: React.FC<HeaderProps> = ({
  currentRoute,
  onNavigate,
  currentUser,
  onLogout,
  backendStatus,
}) => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const cleanRoute = currentRoute.replace(/^#\/?/, '').split('?')[0].toLowerCase();
  const isLandingPage = cleanRoute === '' || cleanRoute === '/';

  return (
    <header className="sticky top-0 z-50 py-3 px-4 sm:px-6 lg:px-8 transition-all">
      <div className="max-w-7xl mx-auto flex items-center justify-between">
        {/* Brand Logo */}
        <div
          onClick={() => onNavigate('')}
          className="flex items-center space-x-2.5 cursor-pointer group select-none bg-white/80 backdrop-blur-md px-3.5 py-1.5 rounded-full border border-border shadow-xs hover:border-forest/40 transition-colors"
        >
          <div className="w-8 h-8 rounded-full bg-forest text-white flex items-center justify-center shadow-xs">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <span className="font-extrabold text-base tracking-tight text-charcoal group-hover:text-forest transition-colors">
            FraudLens
          </span>
        </div>

        {/* Center Floating Pill Navigation */}
        <nav className="hidden md:flex items-center space-x-1 bg-white/85 backdrop-blur-md border border-border px-3 py-1.5 rounded-full shadow-xs">
          <button
            type="button"
            onClick={() => onNavigate('')}
            className={`px-3.5 py-1.5 rounded-full text-xs font-semibold transition-colors ${
              isLandingPage || cleanRoute === 'overview'
                ? 'bg-forest text-white shadow-2xs'
                : 'text-charcoal-muted hover:text-charcoal hover:bg-surface-subtle'
            }`}
          >
            Overview
          </button>

          <button
            type="button"
            onClick={() => onNavigate('message')}
            className={`flex items-center space-x-1.5 px-3.5 py-1.5 rounded-full text-xs font-semibold transition-colors ${
              cleanRoute === 'message'
                ? 'bg-forest text-white shadow-2xs'
                : 'text-charcoal-muted hover:text-charcoal hover:bg-surface-subtle'
            }`}
          >
            <MessageSquareText className="w-3.5 h-3.5" />
            <span>Scam Messages</span>
          </button>

          <button
            type="button"
            onClick={() => onNavigate('url')}
            className={`flex items-center space-x-1.5 px-3.5 py-1.5 rounded-full text-xs font-semibold transition-colors ${
              cleanRoute === 'url'
                ? 'bg-forest text-white shadow-2xs'
                : 'text-charcoal-muted hover:text-charcoal hover:bg-surface-subtle'
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            <span>Phishing URLs</span>
          </button>

          <button
            type="button"
            onClick={() => onNavigate('qr')}
            className={`flex items-center space-x-1.5 px-3.5 py-1.5 rounded-full text-xs font-semibold transition-colors ${
              cleanRoute === 'qr'
                ? 'bg-forest text-white shadow-2xs'
                : 'text-charcoal-muted hover:text-charcoal hover:bg-surface-subtle'
            }`}
          >
            <QrCode className="w-3.5 h-3.5" />
            <span>QR Safety</span>
          </button>
        </nav>

        {/* Right Side: Authentication Controls & Status */}
        <div className="flex items-center space-x-2.5">
          {/* API Status Dot */}
          <div className="hidden xl:flex items-center space-x-1.5 px-3 py-1 rounded-full bg-white/80 backdrop-blur-md border border-border text-[11px] font-mono text-charcoal-muted shadow-2xs">
            <span
              className={`w-2 h-2 rounded-full ${
                backendStatus === 'connected'
                  ? 'bg-emerald-500 animate-pulse'
                  : backendStatus === 'checking'
                  ? 'bg-amber-500'
                  : 'bg-rose-500'
              }`}
            />
            <span>{backendStatus === 'connected' ? 'API Online' : 'Connecting'}</span>
          </div>

          {currentUser ? (
            <div className="flex items-center space-x-2 bg-white/85 backdrop-blur-md border border-border p-1 pl-3 rounded-full shadow-xs">
              <span className="text-xs font-bold text-charcoal truncate max-w-[120px]">
                {currentUser.name}
              </span>
              <button
                type="button"
                onClick={onLogout}
                className="p-1.5 rounded-full hover:bg-rose-50 text-charcoal-muted hover:text-rose-600 transition-colors"
                title="Log Out"
              >
                <LogOut className="w-3.5 h-3.5" />
              </button>
            </div>
          ) : (
            <div className="flex items-center space-x-2">
              <button
                type="button"
                onClick={() => onNavigate('login')}
                className={`px-4 py-2 rounded-full text-xs font-semibold transition-colors bg-white/80 backdrop-blur-md border border-border shadow-2xs ${
                  cleanRoute === 'login'
                    ? 'text-forest font-bold border-forest'
                    : 'text-charcoal hover:text-forest'
                }`}
              >
                Log In
              </button>

              <button
                type="button"
                onClick={() => onNavigate('signup')}
                className="px-5 py-2 rounded-full bg-forest hover:bg-forest-hover text-white text-xs font-bold shadow-xs transition-all flex items-center space-x-1.5"
              >
                <UserPlus className="w-3.5 h-3.5" />
                <span>Get Started</span>
              </button>
            </div>
          )}

          {/* Mobile Menu Toggle Button */}
          <button
            type="button"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="md:hidden p-2 rounded-full bg-white/80 backdrop-blur-md border border-border text-charcoal shadow-xs"
            aria-label="Toggle Navigation Menu"
          >
            {mobileMenuOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Mobile Menu Overlay */}
      {mobileMenuOpen && (
        <div className="md:hidden mt-2 p-4 rounded-3xl bg-white border border-border shadow-lg space-y-2">
          <button
            type="button"
            onClick={() => {
              onNavigate('');
              setMobileMenuOpen(false);
            }}
            className={`w-full text-left py-2.5 px-3 rounded-xl text-xs font-semibold ${
              isLandingPage || cleanRoute === 'overview'
                ? 'bg-forest text-white'
                : 'text-charcoal hover:bg-surface-subtle'
            }`}
          >
            Overview
          </button>

          <button
            type="button"
            onClick={() => {
              onNavigate('message');
              setMobileMenuOpen(false);
            }}
            className={`w-full flex items-center space-x-2 py-2.5 px-3 rounded-xl text-xs font-semibold ${
              cleanRoute === 'message'
                ? 'bg-forest text-white'
                : 'text-charcoal hover:bg-surface-subtle'
            }`}
          >
            <MessageSquareText className="w-4 h-4 text-sage-400" />
            <span>Scam Messages</span>
          </button>

          <button
            type="button"
            onClick={() => {
              onNavigate('url');
              setMobileMenuOpen(false);
            }}
            className={`w-full flex items-center space-x-2 py-2.5 px-3 rounded-xl text-xs font-semibold ${
              cleanRoute === 'url'
                ? 'bg-forest text-white'
                : 'text-charcoal hover:bg-surface-subtle'
            }`}
          >
            <Globe className="w-4 h-4 text-sky-400" />
            <span>Phishing URLs</span>
          </button>

          <button
            type="button"
            onClick={() => {
              onNavigate('qr');
              setMobileMenuOpen(false);
            }}
            className={`w-full flex items-center space-x-2 py-2.5 px-3 rounded-xl text-xs font-semibold ${
              cleanRoute === 'qr'
                ? 'bg-forest text-white'
                : 'text-charcoal hover:bg-surface-subtle'
            }`}
          >
            <QrCode className="w-4 h-4 text-emerald-400" />
            <span>QR Safety Scanner</span>
          </button>

          {currentUser && (
            <div className="pt-2 border-t border-border-subtle">
              <button
                type="button"
                onClick={() => {
                  onLogout();
                  setMobileMenuOpen(false);
                }}
                className="w-full flex items-center space-x-2 py-2 px-3 rounded-xl text-xs font-semibold text-rose-600 hover:bg-rose-50"
              >
                <LogOut className="w-4 h-4" />
                <span>Log Out ({currentUser.name})</span>
              </button>
            </div>
          )}
        </div>
      )}
    </header>
  );
};

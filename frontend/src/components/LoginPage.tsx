import React, { useState } from 'react';
import { ShieldCheck, Eye, EyeOff, ArrowLeft, LogIn, AlertCircle, Lock } from 'lucide-react';
import { loginUser, type AuthUser } from '../api';
import heroBg from '../assets/hero_bg.jpg';

interface LoginPageProps {
  onNavigate: (route: string) => void;
  onLoginSuccess: (user: AuthUser, token: string) => void;
  redirectRoute?: string;
}

export const LoginPage: React.FC<LoginPageProps> = ({
  onNavigate,
  onLoginSuccess,
  redirectRoute,
}) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    if (!email.trim() || !password) {
      setErrorMessage('Please fill in both your email and password.');
      return;
    }

    setIsLoading(true);

    try {
      const data = await loginUser(email.trim(), password);
      onLoginSuccess(data.user, data.token);
      onNavigate(redirectRoute ? redirectRoute : '');
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : 'Invalid credentials. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="relative min-h-screen w-full flex flex-col justify-center items-center px-4 py-12 overflow-hidden bg-black select-none">
      {/* Full-Screen Photographic Background */}
      <img
        src={heroBg}
        alt="FraudLens Security Background"
        className="absolute inset-0 w-full h-full object-cover object-center scale-105"
      />

      {/* Atmospheric Dark Overlay for Contrast & Readability */}
      <div className="absolute inset-0 bg-gradient-to-b from-black/65 via-black/45 to-black/75 backdrop-blur-[1px]" />

      {/* Container */}
      <div className="relative z-10 w-full max-w-md space-y-6">
        {/* Top Header Bar above Card: Back Link & Visible Brand Lockup */}
        <div className="flex items-center justify-between">
          <button
            type="button"
            onClick={() => onNavigate('')}
            className="inline-flex items-center space-x-2 text-xs font-semibold text-white/80 hover:text-white transition-colors group px-1 drop-shadow-sm"
          >
            <ArrowLeft className="w-4 h-4 transition-transform group-hover:-translate-x-1" />
            <span>Back to Home</span>
          </button>

          {/* Visible FraudLens Brand Lockup */}
          <div className="inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-full bg-white/10 backdrop-blur-md border border-white/20 shadow-xs">
            <div className="w-6 h-6 rounded-full bg-forest text-white flex items-center justify-center shadow-2xs">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-300" />
            </div>
            <span className="font-extrabold text-sm tracking-tight text-white drop-shadow-xs">
              FraudLens
            </span>
          </div>
        </div>

        {/* Informative Protected Route Notice */}
        {redirectRoute && (
          <div className="p-3.5 rounded-2xl bg-white/20 backdrop-blur-md border border-white/30 text-white text-xs flex items-center space-x-2.5 shadow-lg">
            <Lock className="w-4 h-4 shrink-0 text-sage-200" />
            <span>Please log in to access the requested security tool.</span>
          </div>
        )}

        {/* Translucent Glassmorphism Card */}
        <div className="bg-white/75 backdrop-blur-xl rounded-3xl border border-white/35 p-8 sm:p-10 shadow-2xl space-y-6">
          <div className="text-center space-y-2">
            <div className="w-12 h-12 rounded-2xl bg-card-mint border border-sage-300 text-forest mx-auto flex items-center justify-center shadow-xs">
              <ShieldCheck className="w-7 h-7" />
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-charcoal tracking-tight">
              Welcome Back
            </h1>
            <p className="text-xs sm:text-sm text-charcoal-muted max-w-xs mx-auto">
              Access your verified FraudLens account and detection tools.
            </p>
          </div>

          {errorMessage && (
            <div className="p-3.5 rounded-2xl bg-rose-50/90 border border-rose-200 text-rose-800 text-xs flex items-start gap-2.5">
              <AlertCircle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
              <span>{errorMessage}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-charcoal block">Email Address</label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@domain.com"
                className="w-full px-4 py-3 rounded-xl bg-white/90 border border-white/40 text-charcoal text-sm focus:outline-none focus:ring-2 focus:ring-forest focus:bg-white shadow-2xs transition"
              />
            </div>

            <div className="space-y-1.5">
              <div className="flex justify-between items-center">
                <label className="text-xs font-semibold text-charcoal block">Password</label>
              </div>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full px-4 py-3 rounded-xl bg-white/90 border border-white/40 text-charcoal text-sm focus:outline-none focus:ring-2 focus:ring-forest focus:bg-white shadow-2xs transition pr-11"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-charcoal-muted hover:text-charcoal p-1"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full py-3.5 px-4 rounded-full bg-forest hover:bg-forest-hover text-white font-semibold text-sm flex items-center justify-center space-x-2 shadow-lg transition-all disabled:opacity-50 mt-2 transform hover:scale-[1.01] active:scale-[0.99]"
            >
              {isLoading ? (
                <span>Authenticating...</span>
              ) : (
                <>
                  <LogIn className="w-4 h-4" />
                  <span>Log In</span>
                </>
              )}
            </button>
          </form>

          <div className="pt-4 border-t border-border-subtle text-center text-xs text-charcoal-muted">
            Don&apos;t have an account yet?{' '}
            <button
              type="button"
              onClick={() => onNavigate(redirectRoute ? `signup?redirect=${redirectRoute}` : 'signup')}
              className="font-bold text-forest hover:text-forest-dark underline underline-offset-2"
            >
              Create Account
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;

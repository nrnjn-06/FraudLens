import React from 'react';
import {
  ArrowRight,
  Lock,
  Cpu,
  Scale,
  Sparkles,
} from 'lucide-react';

import heroBg from '../assets/hero_bg.jpg';

interface LandingPageProps {
  onNavigate: (route: string) => void;
}

export const LandingPage: React.FC<LandingPageProps> = ({ onNavigate }) => {
  return (
    <div className="relative w-full h-screen min-h-[100dvh] flex items-center justify-center text-center overflow-hidden bg-black select-none">
      {/* Edge-to-Edge Full-Bleed Photographic Background */}
      <img
        src={heroBg}
        alt="Digital security in daily life"
        className="absolute inset-0 w-full h-full object-cover object-center scale-105"
      />

      {/* Atmospheric Dark Gradient Vignette for Crystal Clear Text Legibility */}
      <div className="absolute inset-0 bg-gradient-to-b from-black/65 via-black/45 to-black/75" />

      {/* Hero Content - Centered Horizontally & Vertically */}
      <div className="relative z-10 max-w-4xl mx-auto px-6 py-12 space-y-8">
        {/* Small Pill Label */}
        <div className="inline-flex items-center space-x-2 px-4 py-1.5 rounded-full bg-white/15 backdrop-blur-md border border-white/25 text-white text-xs font-semibold shadow-xs">
          <Sparkles className="w-3.5 h-3.5 text-sage-200" />
          <span>Unified Fraud &amp; Deception Defense</span>
        </div>

        {/* Main Heading & FraudLens Brand Lockup */}
        <div className="space-y-3">
          <h1 className="text-4xl sm:text-6xl lg:text-7xl font-extrabold tracking-tight text-white leading-[1.08] drop-shadow-sm">
            FraudLens
          </h1>
          <div className="text-2xl sm:text-3xl lg:text-4xl font-extrabold tracking-tight text-emerald-400 drop-shadow-sm">
            Stay One Step Ahead of Scams.
          </div>
        </div>

        {/* Supporting Text */}
        <p className="text-base sm:text-lg text-white/90 max-w-xl mx-auto font-normal leading-relaxed drop-shadow-xs">
          Check suspicious messages, inspect potentially dangerous links, and scan QR codes before you trust them.
        </p>

        {/* Action Buttons: Log In (Primary) & Create Account (Secondary) */}
        <div className="pt-4 flex flex-col sm:flex-row items-center justify-center gap-4">
          <button
            type="button"
            onClick={() => onNavigate('login')}
            className="w-full sm:w-auto px-9 py-4 rounded-full bg-white hover:bg-neutral-100 text-charcoal font-bold text-sm shadow-xl transition-all transform hover:scale-[1.02] active:scale-[0.99] flex items-center justify-center space-x-2"
          >
            <span>Log In</span>
            <ArrowRight className="w-4 h-4 text-forest" />
          </button>

          <button
            type="button"
            onClick={() => onNavigate('signup')}
            className="w-full sm:w-auto px-8 py-4 rounded-full bg-white/20 hover:bg-white/30 text-white backdrop-blur-md border border-white/35 font-semibold text-sm transition-all"
          >
            Create Account
          </button>
        </div>

        {/* Trust Indicators */}
        <div className="pt-8 flex flex-wrap justify-center gap-3 text-xs text-white/85 font-medium">
          <span className="inline-flex items-center space-x-1.5 px-3.5 py-1.5 rounded-full bg-white/10 backdrop-blur-xs border border-white/20">
            <Lock className="w-3.5 h-3.5 text-sage-300" />
            <span>Zero Data Egress</span>
          </span>
          <span className="inline-flex items-center space-x-1.5 px-3.5 py-1.5 rounded-full bg-white/10 backdrop-blur-xs border border-white/20">
            <Cpu className="w-3.5 h-3.5 text-sage-300" />
            <span>Offline Machine Learning</span>
          </span>
          <span className="inline-flex items-center space-x-1.5 px-3.5 py-1.5 rounded-full bg-white/10 backdrop-blur-xs border border-white/20">
            <Scale className="w-3.5 h-3.5 text-sage-300" />
            <span>Statistical Humility</span>
          </span>
        </div>
      </div>
    </div>
  );
};

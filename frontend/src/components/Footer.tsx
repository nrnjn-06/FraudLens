import React from 'react';
import { ShieldCheck, Terminal, ExternalLink } from 'lucide-react';
import { API_BASE_URL } from '../api';

interface FooterProps {
  onNavigate: (route: string) => void;
}

export const Footer: React.FC<FooterProps> = ({ onNavigate }) => {
  return (
    <footer className="relative z-20 border-t border-[#1d2b24] bg-[#111915] text-white py-14 text-xs mt-0 shadow-2xl">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-8">
        <div className="flex flex-col md:flex-row items-center justify-between gap-6">
          {/* Logo & Platform Name */}
          <div
            onClick={() => onNavigate('')}
            className="flex items-center space-x-2.5 cursor-pointer group select-none"
          >
            <div className="w-8 h-8 rounded-full bg-forest text-white flex items-center justify-center shadow-xs group-hover:bg-forest-hover transition-colors">
              <ShieldCheck className="w-4 h-4 text-emerald-300" />
            </div>
            <span className="font-extrabold text-base tracking-tight text-white group-hover:text-emerald-300 transition-colors">
              FraudLens
            </span>
          </div>

          {/* Clean Navigation Links */}
          <div className="flex flex-wrap items-center justify-center gap-x-7 gap-y-2.5 text-xs font-medium">
            <button
              type="button"
              onClick={() => onNavigate('')}
              className="text-white/80 hover:text-emerald-300 transition-colors"
            >
              Overview
            </button>
            <button
              type="button"
              onClick={() => onNavigate('message')}
              className="text-white/80 hover:text-emerald-300 transition-colors"
            >
              Scam Messages
            </button>
            <button
              type="button"
              onClick={() => onNavigate('url')}
              className="text-white/80 hover:text-emerald-300 transition-colors"
            >
              Phishing URLs
            </button>
            <button
              type="button"
              onClick={() => onNavigate('qr')}
              className="text-white/80 hover:text-emerald-300 transition-colors"
            >
              QR Safety
            </button>
            <a
              href={`${API_BASE_URL}/docs`}
              target="_blank"
              rel="noreferrer"
              className="text-white/80 hover:text-emerald-300 transition-colors inline-flex items-center space-x-1.5"
            >
              <Terminal className="w-3.5 h-3.5 text-emerald-400" />
              <span>FastAPI Docs</span>
              <ExternalLink className="w-2.5 h-2.5 text-white/40" />
            </a>
          </div>
        </div>

        {/* Disclaimer and Attribution */}
        <div className="pt-6 border-t border-[#1d2b24] flex flex-col sm:flex-row items-center justify-between gap-4 text-[11px] text-white/55 leading-relaxed text-center sm:text-left">
          <p className="max-w-2xl">
            FraudLens provides probabilistic machine-learning risk assessments and does not guarantee that a message, URL, QR code, or payment destination is completely safe. Always verify sensitive credentials before taking action.
          </p>
          <p className="whitespace-nowrap font-medium text-white/45">
            © 2026 FraudLens · Privacy-Preserving Security
          </p>
        </div>
      </div>
    </footer>
  );
};

export default Footer;

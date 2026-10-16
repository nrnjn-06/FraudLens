import React, { useEffect, useRef } from 'react';
import {
  MessageSquareText,
  Globe,
  QrCode,
  ArrowRight,
  Lock,
  BarChart3,
  Scale,
  Server,
  AlertOctagon,
  ShieldAlert,
  CheckCircle2,
  HelpCircle,
  Cpu,
  Activity,
  Sparkles,
} from 'lucide-react';
import type { HealthResponse } from '../types/api';
import cardMessage from '../assets/card_message.jpg';
import cardUrl from '../assets/card_url.jpg';
import cardQr from '../assets/card_qr.jpg';
import bgHero from '../assets/backgrounds/overview-hero.jpg';
import bgCapabilities from '../assets/backgrounds/overview-capabilities.jpg';
import bgTaxonomy from '../assets/backgrounds/overview-risk-taxonomy.jpg';
import bgTelemetry from '../assets/backgrounds/overview-telemetry.jpg';

interface HomePageProps {
  onNavigate: (route: string) => void;
  healthData: HealthResponse | null;
  backendStatus: 'connected' | 'offline' | 'checking';
}

interface TelemetryInfo {
  status: 'Active' | 'Available' | 'Offline' | 'Not Configured';
  modelDetail: string;
  isOperational: boolean;
}

/**
 * Format raw backend subsystem telemetry into concise, user-friendly statuses
 * and format subsystem details for clean UI presentation.
 */
const formatSubsystemTelemetry = (subsystemKey: string, raw?: string): TelemetryInfo => {
  if (!raw) {
    return {
      status: 'Offline',
      modelDetail: 'Subsystem unreachable',
      isOperational: false,
    };
  }

  const upper = raw.toUpperCase();

  if (upper.includes('UNAVAILABLE') || upper.includes('OFFLINE') || upper.includes('ERROR')) {
    return {
      status: 'Offline',
      modelDetail: 'Model or service unavailable',
      isOperational: false,
    };
  }

  if (subsystemKey === 'message_detector') {
    return {
      status: 'Active',
      modelDetail: 'TF-IDF + Logistic Regression Model v1.0.0',
      isOperational: true,
    };
  }

  if (subsystemKey === 'url_detector') {
    return {
      status: 'Active',
      modelDetail: 'Random Forest (34 Features) Classifier v1.0.0',
      isOperational: true,
    };
  }

  if (subsystemKey === 'qr_scanner') {
    return {
      status: 'Active',
      modelDetail: 'Computer Vision Scanner & UPI Engine',
      isOperational: true,
    };
  }

  if (subsystemKey === 'threat_intel') {
    if (upper.includes('LOCAL-ONLY') || upper.includes('UNCONFIGURED')) {
      return {
        status: 'Available',
        modelDetail: 'Local-only mode · Providers not configured',
        isOperational: true,
      };
    }
    return {
      status: 'Active',
      modelDetail: 'External Feeds & Cache Active',
      isOperational: true,
    };
  }

  // Generic fallback: clean any remaining stage prefixes
  const cleaned = raw.replace(/^STAGE_\d+(_[A-Z0-9]+)?\s*/gi, '').replace(/^\((.*)\)$/, '$1').trim();
  return {
    status: 'Active',
    modelDetail: cleaned || 'Operational',
    isOperational: true,
  };
};

export const HomePage: React.FC<HomePageProps> = ({
  onNavigate,
  healthData,
  backendStatus,
}) => {
  const heroRef = useRef<HTMLElement>(null);
  const capabilitiesRef = useRef<HTMLElement>(null);
  const taxonomyRef = useRef<HTMLElement>(null);
  const telemetryRef = useRef<HTMLElement>(null);

  const isTransitioningRef = useRef(false);
  const lastScrollYRef = useRef(0);
  const triggeredMapRef = useRef<{ [index: number]: boolean }>({});
  const transitionTimeoutRef = useRef<number | null>(null);
  const isPointerDownRef = useRef(false);

  useEffect(() => {
    lastScrollYRef.current = window.scrollY;

    const sections = [heroRef, capabilitiesRef, taxonomyRef, telemetryRef];

    const handlePointerDown = () => {
      isPointerDownRef.current = true;
    };
    const handlePointerUp = () => {
      isPointerDownRef.current = false;
    };

    window.addEventListener('pointerdown', handlePointerDown, { passive: true });
    window.addEventListener('pointerup', handlePointerUp, { passive: true });
    window.addEventListener('pointercancel', handlePointerUp, { passive: true });

    const isUserInteracting = () => {
      if (isPointerDownRef.current) return true;
      const activeEl = document.activeElement;
      if (activeEl && activeEl !== document.body && activeEl !== document.documentElement) {
        const tagName = activeEl.tagName.toLowerCase();
        if (tagName === 'input' || tagName === 'textarea' || tagName === 'select' || tagName === 'button') {
          return true;
        }
        if (activeEl.getAttribute('role') === 'button' || (activeEl as HTMLElement).isContentEditable) {
          return true;
        }
      }
      return false;
    };

    let rafId: number | null = null;

    const handleScroll = () => {
      if (rafId !== null) return;
      rafId = window.requestAnimationFrame(() => {
        rafId = null;

        const currentScrollY = window.scrollY;
        const isScrollingDown = currentScrollY > lastScrollYRef.current + 1;
        const isScrollingUp = currentScrollY < lastScrollYRef.current - 1;
        lastScrollYRef.current = currentScrollY;

        // If currently executing an auto-transition, suppress intermediate events
        if (isTransitioningRef.current) return;

        const header = document.querySelector('header');
        const headerHeight = header ? header.getBoundingClientRect().height : 0;

        // Check each transitionable segment:
        // Segment 0: Hero -> Capabilities
        // Segment 1: Capabilities -> Taxonomy
        // Segment 2: Taxonomy -> Telemetry
        // Segment 3: Telemetry (Segment 4) is intentionally excluded from auto-transitioning
        for (let i = 0; i < 3; i++) {
          const currentSection = sections[i].current;
          const nextSection = sections[i + 1]?.current;
          if (!currentSection || !nextSection) continue;

          const rect = currentSection.getBoundingClientRect();
          const sectionHeight = currentSection.offsetHeight;
          if (sectionHeight <= 0) continue;

          // How far into the section has been scrolled past the sticky header
          const scrolledIntoSection = headerHeight - rect.top;
          const progress = scrolledIntoSection / sectionHeight;

          // If the user scrolls upward back above ~15% or out of this section, reset the trigger
          if (isScrollingUp && progress < 0.15) {
            triggeredMapRef.current[i] = false;
          }

          // Trigger smooth downward transition when ~25% through current segment
          if (
            isScrollingDown &&
            progress >= 0.24 &&
            progress < 0.90 &&
            !triggeredMapRef.current[i] &&
            !isUserInteracting()
          ) {
            const prefersReducedMotion =
              window.matchMedia?.('(prefers-reduced-motion: reduce)')?.matches ?? false;

            triggeredMapRef.current[i] = true;
            isTransitioningRef.current = true;

            const nextRect = nextSection.getBoundingClientRect();
            const targetY = nextRect.top + window.scrollY - headerHeight;

            window.scrollTo({
              top: Math.max(0, targetY),
              behavior: prefersReducedMotion ? 'auto' : 'smooth',
            });

            // Prevent accidental multi-segment skipping with a ~1000ms cooldown lock
            if (transitionTimeoutRef.current) {
              window.clearTimeout(transitionTimeoutRef.current);
            }
            transitionTimeoutRef.current = window.setTimeout(() => {
              isTransitioningRef.current = false;
              lastScrollYRef.current = window.scrollY;
            }, 1000);

            break; // Transition only one step per downward pass
          }
        }
      });
    };

    window.addEventListener('scroll', handleScroll, { passive: true });

    return () => {
      window.removeEventListener('scroll', handleScroll);
      window.removeEventListener('pointerdown', handlePointerDown);
      window.removeEventListener('pointerup', handlePointerUp);
      window.removeEventListener('pointercancel', handlePointerUp);
      if (rafId !== null) {
        window.cancelAnimationFrame(rafId);
      }
      if (transitionTimeoutRef.current) {
        window.clearTimeout(transitionTimeoutRef.current);
      }
    };
  }, []);

  return (
    <div className="w-full flex flex-col select-none">
      {/* ========================================================= */}
      {/* SEGMENT 1: HERO / INTRODUCTION */}
      {/* ========================================================= */}
      <section
        ref={heroRef}
        id="overview-hero"
        className="relative w-full min-h-[calc(100dvh-4.5rem)] flex flex-col justify-center items-center overflow-hidden py-16 px-4 sm:px-6 lg:px-8 scroll-mt-18"
      >
        {/* Dedicated Background Image 1 */}
        <img
          src={bgHero}
          alt="FraudLens Security Overview"
          className="absolute inset-0 w-full h-full object-cover object-center scale-105"
        />
        {/* Atmospheric Dark Gradient Vignette for Clear Text Legibility */}
        <div className="absolute inset-0 bg-gradient-to-b from-black/75 via-black/55 to-black/80 backdrop-blur-[0.5px]" />

        {/* Hero Content */}
        <div className="relative z-10 w-full max-w-4xl mx-auto text-center space-y-8 animate-fade-in-up">
          <div className="inline-flex items-center space-x-2 px-4 py-1.5 rounded-full bg-white/15 backdrop-blur-md border border-white/25 text-white text-xs font-semibold shadow-xs">
            <Sparkles className="w-3.5 h-3.5 text-sage-200" />
            <span>Multi-Layer Digital Fraud Defense Platform</span>
          </div>

          <h1 className="text-4xl sm:text-6xl lg:text-7xl font-black tracking-tight text-white leading-[1.08] drop-shadow-sm">
            Stay Ahead of{' '}
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 to-teal-300">
              Digital Scams
            </span>
          </h1>

          <p className="text-base sm:text-lg text-white/90 max-w-2xl mx-auto font-normal leading-relaxed drop-shadow-xs">
            FraudLens bridges the critical defense gap between network security and behavioral deception.
            Inspect suspicious SMS messages, fraudulent hyperlinks, and malicious QR codes under a unified,
            explainable risk engine without sending sensitive data to external networks.
          </p>

          {/* Value Proposition Badges */}
          <div className="pt-2 flex flex-wrap justify-center gap-3 text-xs text-white/90 font-medium">
            <span className="inline-flex items-center space-x-1.5 px-4 py-2 rounded-full bg-white/10 backdrop-blur-md border border-white/20 shadow-xs">
              <Lock className="w-3.5 h-3.5 text-emerald-300" />
              <span>Zero Payload Egress</span>
            </span>
            <span className="inline-flex items-center space-x-1.5 px-4 py-2 rounded-full bg-white/10 backdrop-blur-md border border-white/20 shadow-xs">
              <Cpu className="w-3.5 h-3.5 text-emerald-300" />
              <span>Local Machine Learning</span>
            </span>
            <span className="inline-flex items-center space-x-1.5 px-4 py-2 rounded-full bg-white/10 backdrop-blur-md border border-white/20 shadow-xs">
              <Scale className="w-3.5 h-3.5 text-emerald-300" />
              <span>Statistical Humility</span>
            </span>
            <span className="inline-flex items-center space-x-1.5 px-4 py-2 rounded-full bg-white/10 backdrop-blur-md border border-white/20 shadow-xs">
              <BarChart3 className="w-3.5 h-3.5 text-emerald-300" />
              <span>4-Tier Risk Taxonomy</span>
            </span>
          </div>
        </div>
      </section>

      {/* ========================================================= */}
      {/* SEGMENT 2: COMPREHENSIVE DETECTION CAPABILITIES */}
      {/* ========================================================= */}
      <section
        ref={capabilitiesRef}
        id="overview-capabilities"
        className="relative w-full min-h-screen flex flex-col justify-center items-center overflow-hidden py-20 px-4 sm:px-6 lg:px-8 border-t border-white/10 scroll-mt-18"
      >
        {/* Dedicated Background Image 2 */}
        <img
          src={bgCapabilities}
          alt="Comprehensive Detection Capabilities"
          className="absolute inset-0 w-full h-full object-cover object-center scale-105"
        />
        {/* Dark Atmospheric Gradient Overlay */}
        <div className="absolute inset-0 bg-gradient-to-b from-black/80 via-black/65 to-black/85 backdrop-blur-[0.5px]" />

        <div className="relative z-10 w-full max-w-7xl mx-auto space-y-10 animate-fade-in-up">
          <div className="text-center max-w-2xl mx-auto space-y-2">
            <h2 className="text-3xl sm:text-4xl lg:text-5xl font-black text-white tracking-tight drop-shadow-sm">
              Comprehensive Detection Capabilities
            </h2>
            <p className="text-sm sm:text-base text-white/85">
              Select a specialized security tool to analyze messages, web links, or optical codes.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 lg:gap-8">
            {/* Card 1: Scam Message Detection (Translucent Soft Lime / Green) */}
            <div className="rounded-3xl bg-[#DDEFCB]/75 backdrop-blur-xl border border-lime-200/50 p-7 flex flex-col justify-between space-y-6 shadow-2xl hover:shadow-2xl hover:-translate-y-1.5 transition-all duration-300 group">
              <div className="space-y-4">
                {/* Card Header with (01) Badge & Icon */}
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="text-2xl font-black text-charcoal tracking-tight group-hover:text-forest transition-colors">
                      Scam Message<br />Detection
                    </h3>
                  </div>
                  <div className="flex flex-col items-end space-y-1.5">
                    <span className="text-xs font-mono font-bold text-charcoal/60">(01)</span>
                    <div className="w-9 h-9 rounded-full bg-white/80 border border-lime-300/80 flex items-center justify-center text-forest shadow-xs">
                      <MessageSquareText className="w-4 h-4" />
                    </div>
                  </div>
                </div>

                {/* Inset Photo with Dark Overlay Pill */}
                <div className="relative rounded-2xl overflow-hidden shadow-sm aspect-[16/10] bg-lime-900/10">
                  <img
                    src={cardMessage}
                    alt="Scam Message Detection Preview"
                    className="w-full h-full object-cover object-center group-hover:scale-105 transition-transform duration-500"
                  />
                  <div className="absolute inset-0 bg-gradient-to-t from-black/75 via-black/20 to-transparent" />
                  <div className="absolute bottom-3 left-3 right-3 px-3.5 py-1.5 rounded-full bg-black/60 backdrop-blur-md text-white text-[11px] font-medium border border-white/20 text-center">
                    NLP Heuristics &amp; Span Highlighting
                  </div>
                </div>

                {/* Concise Description */}
                <p className="text-xs sm:text-sm text-charcoal-muted leading-relaxed font-normal">
                  Natural language processing paired with 7 behavioral heuristics to catch urgency, impersonation, and fraudulent payment prompts.
                </p>
              </div>

              <button
                type="button"
                onClick={() => onNavigate('message')}
                className="w-full py-3.5 px-5 rounded-full bg-forest hover:bg-forest-hover text-white font-semibold text-xs flex items-center justify-center space-x-2 shadow-md transition-all group-hover:scale-[1.01]"
              >
                <span>Analyze Message</span>
                <ArrowRight className="w-4 h-4 transition-transform group-hover:translate-x-1" />
              </button>
            </div>

            {/* Card 2: Phishing URL Detection (Translucent Soft Airy Blue) */}
            <div className="rounded-3xl bg-[#DCECF7]/75 backdrop-blur-xl border border-sky-200/50 p-7 flex flex-col justify-between space-y-6 shadow-2xl hover:shadow-2xl hover:-translate-y-1.5 transition-all duration-300 group">
              <div className="space-y-4">
                {/* Card Header with (02) Badge & Icon */}
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="text-2xl font-black text-charcoal tracking-tight group-hover:text-forest transition-colors">
                      Phishing URL<br />Detection
                    </h3>
                  </div>
                  <div className="flex flex-col items-end space-y-1.5">
                    <span className="text-xs font-mono font-bold text-charcoal/60">(02)</span>
                    <div className="w-9 h-9 rounded-full bg-white/80 border border-sky-300/80 flex items-center justify-center text-forest shadow-xs">
                      <Globe className="w-4 h-4" />
                    </div>
                  </div>
                </div>

                {/* Inset Photo with Dark Overlay Pill */}
                <div className="relative rounded-2xl overflow-hidden shadow-sm aspect-[16/10] bg-sky-900/10">
                  <img
                    src={cardUrl}
                    alt="Phishing URL Detection Preview"
                    className="w-full h-full object-cover object-center group-hover:scale-105 transition-transform duration-500"
                  />
                  <div className="absolute inset-0 bg-gradient-to-t from-black/75 via-black/20 to-transparent" />
                  <div className="absolute bottom-3 left-3 right-3 px-3.5 py-1.5 rounded-full bg-black/60 backdrop-blur-md text-white text-[11px] font-medium border border-white/20 text-center">
                    34 Lexical Features &amp; Spoofing Forensics
                  </div>
                </div>

                {/* Concise Description */}
                <p className="text-xs sm:text-sm text-charcoal-muted leading-relaxed font-normal">
                  Examines web addresses via an offline 34-feature Random Forest model and Levenshtein distance checks without dispatching HTTP queries.
                </p>
              </div>

              <button
                type="button"
                onClick={() => onNavigate('url')}
                className="w-full py-3.5 px-5 rounded-full bg-forest hover:bg-forest-hover text-white font-semibold text-xs flex items-center justify-center space-x-2 shadow-md transition-all group-hover:scale-[1.01]"
              >
                <span>Check URL</span>
                <ArrowRight className="w-4 h-4 transition-transform group-hover:translate-x-1" />
              </button>
            </div>

            {/* Card 3: QR Code Safety Scanner (Translucent Pale Mint / Sage) */}
            <div className="rounded-3xl bg-[#D7EBE2]/75 backdrop-blur-xl border border-emerald-200/50 p-7 flex flex-col justify-between space-y-6 shadow-2xl hover:shadow-2xl hover:-translate-y-1.5 transition-all duration-300 group">
              <div className="space-y-4">
                {/* Card Header with (03) Badge & Icon */}
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="text-2xl font-black text-charcoal tracking-tight group-hover:text-forest transition-colors">
                      QR Code Safety<br />Scanner
                    </h3>
                  </div>
                  <div className="flex flex-col items-end space-y-1.5">
                    <span className="text-xs font-mono font-bold text-charcoal/60">(03)</span>
                    <div className="w-9 h-9 rounded-full bg-white/80 border border-emerald-300/80 flex items-center justify-center text-forest shadow-xs">
                      <QrCode className="w-4 h-4" />
                    </div>
                  </div>
                </div>

                {/* Inset Photo with Dark Overlay Pill */}
                <div className="relative rounded-2xl overflow-hidden shadow-sm aspect-[16/10] bg-emerald-900/10">
                  <img
                    src={cardQr}
                    alt="QR Safety Scanner Preview"
                    className="w-full h-full object-cover object-center group-hover:scale-105 transition-transform duration-500"
                  />
                  <div className="absolute inset-0 bg-gradient-to-t from-black/75 via-black/20 to-transparent" />
                  <div className="absolute bottom-3 left-3 right-3 px-3.5 py-1.5 rounded-full bg-black/60 backdrop-blur-md text-white text-[11px] font-medium border border-white/20 text-center">
                    Computer Vision &amp; UPI Safeguards
                  </div>
                </div>

                {/* Concise Description */}
                <div>
                  <p className="text-xs sm:text-sm text-charcoal-muted leading-relaxed font-normal">
                    Decodes optical barcodes in an isolated computer vision sandbox, inspects UPI parameters, and routes hidden web destinations safely.
                  </p>
                  <span className="text-[10px] text-charcoal-faint block mt-1">
                    Artwork illustration · Analysis executes locally without remote camera streaming
                  </span>
                </div>
              </div>

              <button
                type="button"
                onClick={() => onNavigate('qr')}
                className="w-full py-3.5 px-5 rounded-full bg-forest hover:bg-forest-hover text-white font-semibold text-xs flex items-center justify-center space-x-2 shadow-md transition-all group-hover:scale-[1.01]"
              >
                <span>Scan QR Code</span>
                <ArrowRight className="w-4 h-4 transition-transform group-hover:translate-x-1" />
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* ========================================================= */}
      {/* SEGMENT 3: CALIBRATED RISK CLASSIFICATION FRAMEWORK */}
      {/* ========================================================= */}
      <section
        ref={taxonomyRef}
        id="overview-risk-taxonomy"
        className="relative w-full min-h-screen flex flex-col justify-center items-center overflow-hidden py-20 px-4 sm:px-6 lg:px-8 border-t border-white/10 scroll-mt-18"
      >
        {/* Dedicated Background Image 3 */}
        <img
          src={bgTaxonomy}
          alt="Risk Taxonomy Framework"
          className="absolute inset-0 w-full h-full object-cover object-center scale-105"
        />
        {/* Dark Atmospheric Gradient Overlay */}
        <div className="absolute inset-0 bg-gradient-to-b from-black/80 via-black/65 to-black/85 backdrop-blur-[0.5px]" />

        <div className="relative z-10 w-full max-w-7xl mx-auto animate-fade-in-up">
          <div className="rounded-3xl bg-white/75 backdrop-blur-xl border border-white/35 p-8 sm:p-10 lg:p-12 space-y-8 shadow-2xl">
            <div className="max-w-2xl space-y-2">
              <span className="text-xs font-bold uppercase tracking-wider text-forest font-mono">
                Unified Risk Taxonomy
              </span>
              <h3 className="text-2xl sm:text-3xl font-extrabold text-charcoal">
                Calibrated Risk Classification Framework
              </h3>
              <p className="text-xs sm:text-sm text-charcoal-muted">
                Every analysis result across all three vectors is mapped to a standardized, accessible 4-tier taxonomy.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
              <div className="p-5 rounded-2xl bg-rose-50/75 backdrop-blur-md border border-rose-200/70 space-y-2.5 shadow-sm">
                <div className="flex items-center space-x-2">
                  <AlertOctagon className="w-4 h-4 text-rose-600" />
                  <span className="font-bold text-rose-900 tracking-wide">HIGH RISK</span>
                </div>
                <p className="text-[11px] text-rose-800 leading-relaxed font-normal">
                  Confirmed threat intelligence match, severe social engineering triggers (credential harvesting, artificial urgency), or high ML phishing probability.
                </p>
              </div>

              <div className="p-5 rounded-2xl bg-amber-50/75 backdrop-blur-md border border-amber-200/70 space-y-2.5 shadow-sm">
                <div className="flex items-center space-x-2">
                  <ShieldAlert className="w-4 h-4 text-amber-600" />
                  <span className="font-bold text-amber-900 tracking-wide">MEDIUM RISK</span>
                </div>
                <p className="text-[11px] text-amber-800 leading-relaxed font-normal">
                  Typosquatting brand lookalikes, suspicious structural anomalies, anomalous subdomains, or conflicting probabilistic indicators requiring caution.
                </p>
              </div>

              <div className="p-5 rounded-2xl bg-emerald-50/75 backdrop-blur-md border border-emerald-200/70 space-y-2.5 shadow-sm">
                <div className="flex items-center space-x-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                  <span className="font-bold text-emerald-900 tracking-wide">LOW RISK</span>
                </div>
                <p className="text-[11px] text-emerald-800 leading-relaxed font-normal">
                  Standard legitimate structural patterns, verified educational security advisories, or recognized benign conversational contexts.
                </p>
              </div>

              <div className="p-5 rounded-2xl bg-stone-50/75 backdrop-blur-md border border-stone-200/70 space-y-2.5 shadow-sm">
                <div className="flex items-center space-x-2">
                  <HelpCircle className="w-4 h-4 text-stone-600" />
                  <span className="font-bold text-stone-900 tracking-wide">UNABLE TO VERIFY</span>
                </div>
                <p className="text-[11px] text-stone-800 leading-relaxed font-normal">
                  Ambiguous structure, unsupported URL schemes, damaged optical barcode symbols, or missing contextual indicators.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ========================================================= */}
      {/* SEGMENT 4: SYSTEM ARCHITECTURE & SUBSYSTEM TELEMETRY */}
      {/* ========================================================= */}
      <section
        ref={telemetryRef}
        id="overview-telemetry"
        className="relative w-full min-h-screen flex flex-col justify-center items-center overflow-hidden py-20 px-4 sm:px-6 lg:px-8 border-t border-white/10 scroll-mt-18"
      >
        {/* Dedicated Background Image 4 */}
        <img
          src={bgTelemetry}
          alt="System Architecture & Subsystem Telemetry"
          className="absolute inset-0 w-full h-full object-cover object-center scale-105"
        />
        {/* Dark Atmospheric Gradient Overlay */}
        <div className="absolute inset-0 bg-gradient-to-b from-black/80 via-black/65 to-black/85 backdrop-blur-[0.5px]" />

        <div className="relative z-10 w-full max-w-7xl mx-auto animate-fade-in-up">
          <div className="rounded-3xl bg-white/75 backdrop-blur-xl border border-white/35 p-8 sm:p-10 lg:p-12 space-y-8 shadow-2xl">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-4">
              <div className="flex items-center space-x-3">
                <div className="p-2.5 rounded-2xl bg-card-green text-forest border border-lime-300/60 shadow-2xs">
                  <Server className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-charcoal">System Architecture &amp; Subsystem Telemetry</h3>
                  <p className="text-xs text-charcoal-muted">
                    FastAPI backend with local model inference and operational subsystem verification.
                  </p>
                </div>
              </div>

              <div className="flex items-center space-x-2 text-xs">
                <span className="text-charcoal-muted font-medium">Platform Status:</span>
                {backendStatus === 'connected' ? (
                  <span className="px-3.5 py-1 rounded-full bg-emerald-100 text-emerald-800 border border-emerald-300 font-semibold flex items-center gap-1.5 shadow-2xs">
                    <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
                    Operational
                  </span>
                ) : backendStatus === 'checking' ? (
                  <span className="px-3.5 py-1 rounded-full bg-amber-100 text-amber-800 border border-amber-300 font-semibold">
                    Connecting...
                  </span>
                ) : (
                  <span className="px-3.5 py-1 rounded-full bg-rose-100 text-rose-800 border border-rose-300 font-semibold">
                    Backend Offline
                  </span>
                )}
              </div>
            </div>

            {/* Clean Operational Telemetry Cards */}
            {healthData && (
              <div className="space-y-3">
                <div className="flex items-center justify-between text-charcoal-muted text-xs font-semibold">
                  <span className="flex items-center gap-1.5">
                    <Activity className="w-3.5 h-3.5 text-forest" />
                    Subsystem Readiness &amp; Operational Models
                  </span>
                  <span className="text-[11px] font-mono text-charcoal-faint">
                    Updated: {new Date(healthData.timestamp).toLocaleTimeString()}
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {/* Message Engine Telemetry */}
                  {(() => {
                    const info = formatSubsystemTelemetry('message_detector', healthData.subsystems.message_detector);
                    return (
                      <div className="p-4 rounded-2xl bg-white/70 backdrop-blur-md border border-white/45 space-y-2 shadow-2xs">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-charcoal">Message Engine</span>
                          <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${
                            info.status === 'Active'
                              ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                              : 'bg-rose-50 text-rose-800 border-rose-200'
                          }`}>
                            {info.status}
                          </span>
                        </div>
                        <p className="text-[11px] text-charcoal-muted leading-tight font-medium">
                          {info.modelDetail}
                        </p>
                      </div>
                    );
                  })()}

                  {/* URL Engine Telemetry */}
                  {(() => {
                    const info = formatSubsystemTelemetry('url_detector', healthData.subsystems.url_detector);
                    return (
                      <div className="p-4 rounded-2xl bg-white/70 backdrop-blur-md border border-white/45 space-y-2 shadow-2xs">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-charcoal">URL Engine</span>
                          <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${
                            info.status === 'Active'
                              ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                              : 'bg-rose-50 text-rose-800 border-rose-200'
                          }`}>
                            {info.status}
                          </span>
                        </div>
                        <p className="text-[11px] text-charcoal-muted leading-tight font-medium">
                          {info.modelDetail}
                        </p>
                      </div>
                    );
                  })()}

                  {/* QR Engine Telemetry */}
                  {(() => {
                    const info = formatSubsystemTelemetry('qr_scanner', healthData.subsystems.qr_scanner);
                    return (
                      <div className="p-4 rounded-2xl bg-white/70 backdrop-blur-md border border-white/45 space-y-2 shadow-2xs">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-charcoal">QR Engine</span>
                          <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${
                            info.status === 'Active'
                              ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                              : 'bg-rose-50 text-rose-800 border-rose-200'
                          }`}>
                            {info.status}
                          </span>
                        </div>
                        <p className="text-[11px] text-charcoal-muted leading-tight font-medium">
                          {info.modelDetail}
                        </p>
                      </div>
                    );
                  })()}
                </div>
              </div>
            )}

            {/* API Routes Overview */}
            <div className="pt-2 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
              <div className="p-3.5 rounded-2xl bg-white/60 backdrop-blur-md border border-white/40 space-y-1.5 shadow-2xs">
                <div className="flex items-center justify-between">
                  <span className="text-emerald-700 font-bold">GET /health</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-white/80 border border-white/40 text-charcoal-muted font-sans">
                    Active
                  </span>
                </div>
                <p className="text-[11px] text-charcoal-muted font-sans">
                  Heartbeat telemetry and subsystem readiness verification.
                </p>
              </div>

              <div className="p-3.5 rounded-2xl bg-white/60 backdrop-blur-md border border-white/40 space-y-1.5 shadow-2xs">
                <div className="flex items-center justify-between">
                  <span className="text-forest font-bold">POST /analyze-message</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-white/80 border border-white/40 text-charcoal-muted font-sans">
                    Active
                  </span>
                </div>
                <p className="text-[11px] text-charcoal-muted font-sans">
                  NLP text classification &amp; entity span extraction.
                </p>
              </div>

              <div className="p-3.5 rounded-2xl bg-white/60 backdrop-blur-md border border-white/40 space-y-1.5 shadow-2xs">
                <div className="flex items-center justify-between">
                  <span className="text-forest font-bold">POST /analyze-url</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-white/80 border border-white/40 text-charcoal-muted font-sans">
                    Active
                  </span>
                </div>
                <p className="text-[11px] text-charcoal-muted font-sans">
                  34-feature Random Forest phishing probability calculation.
                </p>
              </div>

              <div className="p-3.5 rounded-2xl bg-white/60 backdrop-blur-md border border-white/40 space-y-1.5 shadow-2xs">
                <div className="flex items-center justify-between">
                  <span className="text-forest font-bold">POST /analyze-qr</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-white/80 border border-white/40 text-charcoal-muted font-sans">
                    Active
                  </span>
                </div>
                <p className="text-[11px] text-charcoal-muted font-sans">
                  Computer vision barcode decoding &amp; UPI payload inspection.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};

export default HomePage;

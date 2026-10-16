import React, { useState } from 'react';
import type { URLAnalysisResponse, UnifiedRiskClassification } from '../types/api';
import {
  Globe,
  ShieldAlert,
  CheckCircle2,
  AlertOctagon,
  HelpCircle,
  Sparkles,
  Send,
  RefreshCw,
  Server,
  Hash,
  AlertTriangle,
  Cpu,
  Layers,
  ArrowLeft,
  BookOpen,
} from 'lucide-react';
import { UnifiedEvidenceViewer } from './UnifiedEvidenceViewer';
import { ThreatIntelCard } from './ThreatIntelCard';
import { DomainIntelligenceCard } from './DomainIntelligenceCard';
import { RecommendationCard } from './RecommendationCard';
import { API_BASE_URL, extractApiErrorMessage } from '../api';
import bgUrl from '../assets/backgrounds/phishing-url-background.jpg';

const PRESET_URLS = [
  {
    name: 'Phishing Brand Lookalike',
    url: 'https://paypal.com.account-update.xyz/login.php?token=123',
  },
  {
    name: 'Malicious IP Address Host',
    url: 'http://192.168.1.100:8080/admin/login.php',
  },
  {
    name: 'Lookalike Typosquatting',
    url: 'http://paypa1-security.com/verify',
  },
  {
    name: 'Sensitive Auth Tokens in URL',
    url: 'https://secure-login.portal.com/auth?token=948201&session_id=user_sess_xyz&pass=my_secret',
  },
  {
    name: 'Anomalous Banking Subdomain',
    url: 'https://sub.portal.sbi.co.in/banking',
  },
  {
    name: 'Authoritative Web Search',
    url: 'https://www.google.com/search?q=fraudlens',
  },
  {
    name: 'Legitimate Technology Portal',
    url: 'https://apple.com/macbook-pro',
  },
];

const sanitizeUrlForDisplay = (urlStr: string): string => {
  try {
    const urlObj = new URL(urlStr.startsWith('http') ? urlStr : `http://${urlStr}`);
    let modified = false;
    urlObj.searchParams.forEach((_, key) => {
      if (/token|secret|auth|pass|pwd|session|otp|key|cred|sig|pin|jwt/i.test(key)) {
        urlObj.searchParams.set(key, '••••••••');
        modified = true;
      }
    });
    return modified ? urlObj.toString() : urlStr;
  } catch {
    return urlStr;
  }
};

interface URLAnalyzerProps {
  onBackToOverview?: () => void;
}

export const URLAnalyzer: React.FC<URLAnalyzerProps> = ({ onBackToOverview }) => {
  const [inputUrl, setInputUrl] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<URLAnalysisResponse | null>(null);

  const handleAnalyze = async (urlToAnalyze?: string) => {
    const target = (urlToAnalyze ?? inputUrl).trim();
    if (!target) {
      setError('Please enter a target URL to analyze.');
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`${API_BASE_URL}/analyze-url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: target }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        throw new Error(extractApiErrorMessage(errorData, `Server returned ${response.status} error`));
      }

      const data: URLAnalysisResponse = await response.json();
      setResult(data);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('An unexpected network or server error occurred.');
      }
      setResult(null);
    } finally {
      setIsLoading(false);
    }
  };

  const handlePresetClick = (presetUrl: string) => {
    setInputUrl(presetUrl);
    handleAnalyze(presetUrl);
  };

  const renderClassificationBadge = (classification: UnifiedRiskClassification) => {
    switch (classification) {
      case 'HIGH RISK':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-rose-100 text-rose-800 border border-rose-300 shadow-sm">
            <AlertOctagon className="w-4 h-4 text-rose-600" />
            HIGH RISK
          </span>
        );
      case 'MEDIUM RISK':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-amber-100 text-amber-800 border border-amber-300 shadow-sm">
            <ShieldAlert className="w-4 h-4 text-amber-600" />
            MEDIUM RISK
          </span>
        );
      case 'LOW RISK':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-emerald-100 text-emerald-800 border border-emerald-300 shadow-sm">
            <CheckCircle2 className="w-4 h-4 text-emerald-600" />
            LOW RISK
          </span>
        );
      case 'UNABLE TO VERIFY':
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-stone-100 text-stone-700 border border-stone-300 shadow-sm">
            <HelpCircle className="w-4 h-4 text-stone-500" />
            UNABLE TO VERIFY
          </span>
        );
    }
  };

  return (
    <div className="relative min-h-screen w-full py-8 px-4 sm:px-6 lg:px-8 overflow-hidden">
      {/* Dedicated Background Image 6 */}
      <img
        src={bgUrl}
        alt="Phishing URL Forensics Background"
        className="fixed inset-0 w-full h-full object-cover object-center scale-105 pointer-events-none -z-10"
      />
      {/* Subtle Atmospheric Dark Vignette Overlay for Depth & High Contrast */}
      <div className="fixed inset-0 bg-gradient-to-b from-black/75 via-black/55 to-black/80 pointer-events-none -z-10 backdrop-blur-[1px]" />

      <div className="relative z-10 max-w-7xl mx-auto space-y-8">
        {/* Back to Overview Bar */}
        {onBackToOverview && (
          <button
            type="button"
            onClick={onBackToOverview}
            className="inline-flex items-center space-x-2 text-xs font-semibold text-charcoal bg-white/75 backdrop-blur-xl px-4 py-2 rounded-full border border-white/35 shadow-md hover:border-forest/40 transition-colors group"
          >
            <ArrowLeft className="w-4 h-4 transition-transform group-hover:-translate-x-0.5 text-forest" />
            <span>Back to Overview</span>
          </button>
        )}

        {/* Main Container */}
        <div className="bg-white/75 backdrop-blur-xl rounded-3xl sm:rounded-4xl border border-white/35 p-6 md:p-10 space-y-8 shadow-2xl">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-6">
          <div>
            <div className="flex items-center space-x-2 text-forest text-xs font-bold uppercase tracking-wider mb-1 font-mono">
              <Globe className="w-4 h-4" />
              <span>Phishing URL Detection</span>
            </div>
            <h1 className="text-2xl sm:text-3xl lg:text-4xl font-extrabold text-charcoal tracking-tight">
              Phishing URL &amp; Domain Inspector
            </h1>
            <p className="text-xs sm:text-sm text-charcoal-muted mt-2 max-w-2xl leading-relaxed">
              Inspect suspicious web addresses with a 34-feature Random Forest model, Levenshtein brand
              typosquatting detection, and offline domain forensics. Zero network traffic is dispatched to submitted hosts.
            </p>
          </div>

          {result && renderClassificationBadge(result.classification)}
        </div>

        {/* Preset Buttons */}
        <div className="space-y-2.5">
          <span className="text-xs font-semibold text-charcoal flex items-center space-x-1.5">
            <Sparkles className="w-3.5 h-3.5 text-forest" />
            <span>Test Benchmark Scenarios:</span>
          </span>
          <div className="flex flex-wrap gap-2">
            {PRESET_URLS.map((preset) => (
              <button
                key={preset.name}
                type="button"
                onClick={() => handlePresetClick(preset.url)}
                className="text-xs px-3.5 py-1.5 rounded-full bg-white/60 backdrop-blur-md hover:bg-white/80 border border-white/40 hover:border-sage-400 text-charcoal transition-colors font-mono shadow-2xs"
              >
                {preset.name}
              </button>
            ))}
          </div>
        </div>

        {/* Input Form */}
        <div className="space-y-3">
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-grow">
              <input
                type="text"
                value={inputUrl}
                onChange={(e) => setInputUrl(e.target.value)}
                placeholder="Enter target URL (e.g. https://secure-login.paypal-update.xyz/verify)"
                className="w-full px-5 py-3.5 rounded-2xl bg-white/90 backdrop-blur-md border border-white/40 text-charcoal placeholder-charcoal-faint text-sm font-mono focus:outline-none focus:border-forest focus:ring-1 focus:ring-forest transition shadow-2xs"
                onKeyDown={(e) => {
                  if (e.key === 'Enter') handleAnalyze();
                }}
              />
              {inputUrl && (
                <button
                  type="button"
                  onClick={() => setInputUrl('')}
                  className="absolute right-3.5 top-1/2 -translate-y-1/2 text-xs text-charcoal-muted hover:text-charcoal font-mono px-2 py-1 rounded hover:bg-white/80"
                >
                  Clear
                </button>
              )}
            </div>

            <button
              type="button"
              onClick={() => handleAnalyze()}
              disabled={isLoading || !inputUrl.trim()}
              className="px-7 py-3.5 rounded-full bg-forest hover:bg-forest-hover disabled:opacity-50 disabled:cursor-not-allowed text-white text-xs font-bold flex items-center justify-center gap-2 transition shadow-xs shrink-0"
            >
              {isLoading ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Analyzing URL...</span>
                </>
              ) : (
                <>
                  <Send className="w-3.5 h-3.5" />
                  <span>Check URL</span>
                </>
              )}
            </button>
          </div>

          {error && (
            <div className="p-3.5 rounded-xl bg-rose-50 border border-rose-200 text-xs text-rose-800 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}
        </div>

        {/* Analysis Results Display */}
        {result && (
          <div className="space-y-6 pt-6 border-t border-border">
            {/* Main Verdict & Statistical Humility Notice */}
            <div className="p-4 rounded-xl bg-white/70 backdrop-blur-md border border-white/45 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-sm">
              <div>
                <div className="font-mono text-xs text-charcoal break-all mb-1 flex items-center gap-1.5">
                  <span className="text-charcoal-muted font-semibold">Target:</span>
                  <span className="text-sage-900 font-bold">{sanitizeUrlForDisplay(result.target_url)}</span>
                </div>
                <span className="text-[10px] font-mono font-bold text-charcoal-muted uppercase tracking-wider">
                  Primary Assessment Verdict
                </span>
                <div className="flex items-center gap-3 mt-1">
                  {renderClassificationBadge(result.classification)}
                  <span className="text-xs font-mono text-charcoal-muted">
                    Engine Status: <code className="text-sage-800 font-semibold">{result.status}</code>
                  </span>
                </div>
              </div>

              <div className="text-xs text-charcoal-muted max-w-md bg-white/80 backdrop-blur-sm p-3 rounded-xl border border-white/40 shadow-2xs">
                <strong className="text-charcoal">Statistical Humility Guarantee:</strong> This output represents a probabilistic assessment based on structural patterns. It is neither judicial proof of malicious intent nor an absolute guarantee of domain safety.
              </div>
            </div>

            {/* Three Forensic Breakdown Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Card 1: Machine Learning Model */}
              <div className="p-4 rounded-xl bg-white/70 backdrop-blur-md border border-white/45 space-y-3 shadow-sm">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-sage-900 flex items-center gap-1.5">
                    <Cpu className="w-4 h-4 text-sage-600" /> Random Forest Classifier
                  </span>
                  <span className="text-[10px] font-mono text-charcoal-muted">34 Features</span>
                </div>

                {result.model_prediction ? (
                  <div className="space-y-2.5">
                    <div className="flex justify-between items-baseline text-xs">
                      <span className="text-charcoal-muted">Phishing Probability:</span>
                      <span className="font-mono font-bold text-charcoal text-sm">
                        {(result.model_prediction.confidence !== undefined && result.model_prediction.confidence !== null)
                          ? `${(result.model_prediction.confidence * 100).toFixed(1)}%`
                          : 'N/A'}
                      </span>
                    </div>

                    {/* Probability Bar */}
                    <div className="w-full bg-white/50 border border-white/40 h-2 rounded-full overflow-hidden">
                      <div
                        className={`h-full transition-all ${
                          (result.model_prediction.confidence ?? 0) >= 0.6
                            ? 'bg-rose-500'
                            : (result.model_prediction.confidence ?? 0) >= 0.25
                            ? 'bg-amber-500'
                            : 'bg-emerald-500'
                        }`}
                        style={{ width: `${Math.min(100, (result.model_prediction.confidence ?? 0) * 100)}%` }}
                      />
                    </div>

                    <div className="flex justify-between text-[10px] font-mono text-charcoal-muted pt-1">
                      <span>Threshold: 45.0%</span>
                      <span>Model: {result.model_prediction.model_name}</span>
                    </div>
                  </div>
                ) : (
                  <p className="text-xs text-charcoal-muted">Model prediction unavailable.</p>
                )}
              </div>

              {/* Card 2: Typosquatting & Brand Spoofing */}
              <div className="p-4 rounded-xl bg-white/70 backdrop-blur-md border border-white/45 space-y-3 shadow-sm">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-amber-800 flex items-center gap-1.5">
                    <Layers className="w-4 h-4 text-amber-600" /> Typosquatting & Spoofing
                  </span>
                  {result.typosquatting?.is_impersonation ? (
                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-rose-100 text-rose-800 border border-rose-300 font-mono font-bold">
                      Impersonation Flagged
                    </span>
                  ) : (
                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 border border-emerald-300 font-mono font-medium">
                      Clean
                    </span>
                  )}
                </div>

                <div className="text-xs space-y-1.5">
                  <div className="flex justify-between text-charcoal-muted">
                    <span>Target Brand:</span>
                    <span className="font-mono text-charcoal font-semibold">
                      {result.typosquatting?.target_brand || 'None Detected'}
                    </span>
                  </div>
                  {result.typosquatting?.similarity_score !== undefined && result.typosquatting.similarity_score !== null && (
                    <div className="flex justify-between text-charcoal-muted">
                      <span>Similarity Metric:</span>
                      <span className="font-mono text-charcoal font-semibold">
                        {(result.typosquatting.similarity_score * 100).toFixed(0)}%
                      </span>
                    </div>
                  )}
                  <p className="text-[11px] text-charcoal-muted leading-relaxed pt-1.5 border-t border-border-subtle">
                    {result.typosquatting?.details}
                  </p>
                </div>
              </div>

              {/* Card 3: Domain Forensics */}
              <div className="p-4 rounded-xl bg-white/70 backdrop-blur-md border border-white/45 space-y-3 shadow-sm">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-sage-900 flex items-center gap-1.5">
                    <Server className="w-4 h-4 text-sage-600" /> Domain Structure Forensics
                  </span>
                  <span className="text-[10px] font-mono text-charcoal-muted">
                    {result.forensics?.url_length} chars
                  </span>
                </div>

                <div className="text-xs space-y-1 font-mono text-charcoal">
                  <div className="truncate">
                    <span className="text-charcoal-muted">Host: </span>
                    <span className="font-semibold text-charcoal">{result.forensics?.hostname}</span>
                  </div>
                  <div className="truncate">
                    <span className="text-charcoal-muted">Domain: </span>
                    <span className="font-semibold text-charcoal">{result.forensics?.domain}.{result.forensics?.tld}</span>
                  </div>
                  <div className="truncate">
                    <span className="text-charcoal-muted">Subdomain: </span>
                    <span className="text-charcoal">{result.forensics?.subdomain || '(none)'}</span>
                  </div>
                  <div className="truncate">
                    <span className="text-charcoal-muted">IP Host: </span>
                    <span className={result.forensics?.has_ip_address ? 'text-rose-600 font-bold' : 'text-charcoal'}>
                      {result.forensics?.has_ip_address ? 'YES (Raw IP Address)' : 'No (Registered Host)'}
                    </span>
                  </div>
                  {result.forensics?.query_params && Object.keys(result.forensics.query_params).length > 0 && (
                    <div className="pt-2 border-t border-border-subtle text-[11px] space-y-1">
                      <span className="text-charcoal-muted block font-semibold">Query Parameters (Redacted):</span>
                      {Object.entries(result.forensics.query_params).map(([k, v]) => {
                        const isSensitive = /token|secret|auth|pass|pwd|session|otp|key|cred|sig|pin|jwt/i.test(k);
                        return (
                          <div key={k} className="flex justify-between font-mono text-[10px]">
                            <span className="text-charcoal-muted">{k}:</span>
                            <span className={isSensitive ? 'text-amber-800 bg-amber-50 px-1 py-0.5 rounded font-bold' : 'text-charcoal'}>
                              {isSensitive ? '•••••••• (Redacted)' : v}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Domain Intelligence Card */}
            <DomainIntelligenceCard domainIntel={result.domain_intelligence} />

            {/* External Threat Intelligence Card */}
            <ThreatIntelCard threatIntel={result.threat_intelligence} />

            {/* Explainable Risk Indicators */}
            {result.explainable_risk_indicators && result.explainable_risk_indicators.length > 0 && (
              <div className="space-y-3">
                <span className="text-xs font-bold text-charcoal uppercase tracking-wider flex items-center gap-1.5">
                  <Hash className="w-4 h-4 text-sage-600" />
                  Explainable Risk Indicators ({result.explainable_risk_indicators.length})
                </span>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {result.explainable_risk_indicators.map((ind, i) => (
                    <div
                      key={i}
                      className="p-3.5 rounded-xl bg-white/65 backdrop-blur-md border border-white/40 text-xs space-y-1.5 shadow-xs"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono font-bold text-sage-900 text-[11px]">
                          {ind.indicator}
                        </span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-white/80 border border-white/40 text-charcoal-muted font-medium">
                          {ind.contribution_type}
                        </span>
                      </div>
                      <p className="text-charcoal-muted text-[11px] leading-relaxed">
                        {ind.description}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Evidence and Recommendations */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
              <UnifiedEvidenceViewer
                evidence={result.evidence}
                unifiedEvidence={result.unified_evidence}
                title="Unified URL Evidence Hierarchy"
              />

              <RecommendationCard
                structuredRecommendation={result.structured_recommendation}
                recommendations={result.recommendations}
                title="Actionable Security Recommendations"
              />
            </div>
          </div>
        )}
      </div>

      {/* How It Works Section */}
      <div className="rounded-3xl bg-white/75 backdrop-blur-xl border border-white/35 p-6 md:p-8 space-y-4 shadow-2xl">
        <div className="flex items-center space-x-2.5 text-sage-900 font-bold text-base">
          <BookOpen className="w-5 h-5 text-sage-600" />
          <span>How Phishing URL Detection Works</span>
        </div>
        <p className="text-xs text-charcoal-muted leading-relaxed">
          FraudLens evaluates web destinations through multi-layered passive forensics without loading external web pages or exposing IP addresses to malicious servers.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 pt-2">
          <div className="p-4 rounded-xl bg-white/65 backdrop-blur-md border border-white/40 space-y-2 shadow-xs">
            <div className="w-6 h-6 rounded-full bg-sage-100 text-sage-800 font-bold text-xs flex items-center justify-center">
              1
            </div>
            <h4 className="font-bold text-charcoal text-xs">34 Lexical Forensics</h4>
            <p className="text-[11px] text-charcoal-muted leading-relaxed">
              Extracts 34 distinct structural features including character entropy, subdomain depth, hyphen density, and IP host obfuscation.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-white/65 backdrop-blur-md border border-white/40 space-y-2 shadow-xs">
            <div className="w-6 h-6 rounded-full bg-sage-100 text-sage-800 font-bold text-xs flex items-center justify-center">
              2
            </div>
            <h4 className="font-bold text-charcoal text-xs">Random Forest Model</h4>
            <p className="text-[11px] text-charcoal-muted leading-relaxed">
              Ensemble of 100 decision trees trained on millions of legitimate and malicious URLs computes calibrated phishing probabilities.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-white/65 backdrop-blur-md border border-white/40 space-y-2 shadow-xs">
            <div className="w-6 h-6 rounded-full bg-sage-100 text-sage-800 font-bold text-xs flex items-center justify-center">
              3
            </div>
            <h4 className="font-bold text-charcoal text-xs">Brand Typosquatting</h4>
            <p className="text-[11px] text-charcoal-muted leading-relaxed">
              Calculates Levenshtein edit distance and homoglyph substitution against protected financial, e-commerce, and cloud providers.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-white/65 backdrop-blur-md border border-white/40 space-y-2 shadow-xs">
            <div className="w-6 h-6 rounded-full bg-sage-100 text-sage-800 font-bold text-xs flex items-center justify-center">
              4
            </div>
            <h4 className="font-bold text-charcoal text-xs">Privacy-First Intel</h4>
            <p className="text-[11px] text-charcoal-muted leading-relaxed">
              Cross-references threat intelligence feeds using local caches, and masks sensitive credentials (`••••••••`) before rendering.
            </p>
          </div>
        </div>
      </div>
      </div>
    </div>
  );
};

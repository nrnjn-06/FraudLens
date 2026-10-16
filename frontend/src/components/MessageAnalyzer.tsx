import React, { useState } from 'react';
import type { MessageAnalysisResponse, UnifiedRiskClassification } from '../types/api';
import { HighlightedMessage } from './HighlightedMessage';
import {
  MessageSquareText,
  ShieldAlert,
  CheckCircle2,
  AlertOctagon,
  HelpCircle,
  Sparkles,
  Send,
  RefreshCw,
  Tag,
  Link as LinkIcon,
  Phone,
  CreditCard,
  GlobeLock,
  Layers,
  ArrowLeft,
  BookOpen,
} from 'lucide-react';
import { UnifiedEvidenceViewer } from './UnifiedEvidenceViewer';
import { RecommendationCard } from './RecommendationCard';
import { API_BASE_URL, extractApiErrorMessage } from '../api';
import bgMessage from '../assets/backgrounds/scam-message-background.jpg';

const PRESET_MESSAGES = [
  {
    name: 'Bank / KYC Scam',
    text: 'SBI Notice: Your bank account has been suspended due to expired KYC. Please verify your identity and share the 6-digit OTP immediately at http://sbi-kyc-verify.com',
  },
  {
    name: 'Delivery Fee Scam',
    text: 'FedEx Alert: Your shipment #84729 is held at our depot due to unpaid delivery fee of Rs 49. Pay immediately within 24 hours at http://fedex-express-delivery.net to release package.',
  },
  {
    name: 'Work-from-Home Job Scam',
    text: 'Congratulations! Selected for part-time job as HR assistant. Earn Rs 5000 daily with zero experience. Send registration fee to jobactivation@okhdfcbank to start immediately.',
  },
  {
    name: 'Lottery Prize Bait',
    text: 'Lucky Draw Alert: You have won Rs 50,000 cash prize in our annual lottery! Transfer registration fee of Rs 200 to claim your reward before deadline expires today at midnight.',
  },
  {
    name: 'Crypto Investment Scheme',
    text: 'Guaranteed return! Double your money with our automated crypto trading algorithm. 200% return in 24 hours risk-free. Immediate deposit required at http://instant-crypto-returns.biz',
  },
  {
    name: 'Bank Defensive Advisory (Legitimate)',
    text: 'Protect yourself from e-threats: State Bank of India never asks for sensitive information like Password/OTP/CVV. Never share your credentials with anyone.',
  },
  {
    name: 'Benign Conversational Message',
    text: 'I have an urgent meeting with my professor. I will pay for lunch afterwards near the bank.',
  },
];

const SCAM_CATEGORY_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  BANK_KYC: { bg: 'bg-indigo-50', text: 'text-indigo-900', border: 'border-indigo-200' },
  DELIVERY: { bg: 'bg-amber-50', text: 'text-amber-900', border: 'border-amber-200' },
  JOB: { bg: 'bg-teal-50', text: 'text-teal-900', border: 'border-teal-200' },
  PRIZE: { bg: 'bg-emerald-50', text: 'text-emerald-900', border: 'border-emerald-200' },
  INVESTMENT: { bg: 'bg-purple-50', text: 'text-purple-900', border: 'border-purple-200' },
  UNKNOWN: { bg: 'bg-surface-subtle', text: 'text-charcoal-muted', border: 'border-border' },
};

interface MessageAnalyzerProps {
  onBackToOverview?: () => void;
}

export const MessageAnalyzer: React.FC<MessageAnalyzerProps> = ({ onBackToOverview }) => {
  const [inputText, setInputText] = useState(PRESET_MESSAGES[0].text);
  const [isLoading, setIsLoading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<MessageAnalysisResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleAnalyze = async (textToAnalyze?: string) => {
    const text = (textToAnalyze ?? inputText).trim();
    if (!text) {
      setErrorMessage('Please enter a message to analyze.');
      return;
    }

    setIsLoading(true);
    setErrorMessage(null);

    try {
      const res = await fetch(`${API_BASE_URL}/analyze-message`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message_text: text }),
      });

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(extractApiErrorMessage(errorData, `Server returned ${res.status}`));
      }

      const data: MessageAnalysisResponse = await res.json();
      setAnalysisResult(data);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to connect to backend service';
      setErrorMessage(msg);
    } finally {
      setIsLoading(false);
    }
  };

  const getRiskBadge = (classification?: UnifiedRiskClassification) => {
    switch (classification) {
      case 'HIGH RISK':
        return (
          <div className="flex items-center space-x-1.5 px-3 py-1 rounded-full bg-rose-100 border border-rose-300 text-rose-800 text-xs font-bold shadow-sm">
            <AlertOctagon className="w-4 h-4 text-rose-600" />
            <span>HIGH RISK</span>
          </div>
        );
      case 'MEDIUM RISK':
        return (
          <div className="flex items-center space-x-1.5 px-3 py-1 rounded-full bg-amber-100 border border-amber-300 text-amber-800 text-xs font-bold shadow-sm">
            <ShieldAlert className="w-4 h-4 text-amber-600" />
            <span>MEDIUM RISK</span>
          </div>
        );
      case 'LOW RISK':
        return (
          <div className="flex items-center space-x-1.5 px-3 py-1 rounded-full bg-emerald-100 border border-emerald-300 text-emerald-800 text-xs font-bold shadow-sm">
            <CheckCircle2 className="w-4 h-4 text-emerald-600" />
            <span>LOW RISK</span>
          </div>
        );
      default:
        return (
          <div className="flex items-center space-x-1.5 px-3 py-1 rounded-full bg-stone-100 border border-stone-300 text-stone-700 text-xs font-bold shadow-sm">
            <HelpCircle className="w-4 h-4 text-stone-500" />
            <span>UNABLE TO VERIFY</span>
          </div>
        );
    }
  };

  return (
    <div className="relative min-h-screen w-full py-8 px-4 sm:px-6 lg:px-8 overflow-hidden">
      {/* Dedicated Background Image 5 */}
      <img
        src={bgMessage}
        alt="Scam Message Detection Background"
        className="fixed inset-0 w-full h-full object-cover object-center scale-105 pointer-events-none -z-10"
      />
      {/* Subtle Atmospheric Dark Vignette Overlay for Depth & High Contrast */}
      <div className="fixed inset-0 bg-gradient-to-b from-black/70 via-black/55 to-black/75 pointer-events-none -z-10 backdrop-blur-[1px]" />

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

        {/* Main Analyzer Container */}
        <div className="rounded-3xl sm:rounded-4xl bg-white/75 backdrop-blur-xl border border-white/35 p-6 md:p-10 space-y-8 shadow-2xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-6">
          <div>
            <div className="flex items-center space-x-2 text-forest text-xs font-bold uppercase tracking-wider mb-1 font-mono">
              <MessageSquareText className="w-4 h-4" />
              <span>Scam Message Detection</span>
            </div>
            <h1 className="text-2xl sm:text-3xl lg:text-4xl font-extrabold text-charcoal tracking-tight">
              Scam &amp; Deception Message Inspector
            </h1>
            <p className="text-xs sm:text-sm text-charcoal-muted mt-2 max-w-2xl leading-relaxed">
              Inspect suspicious SMS, chat, or email messages for social engineering traps, urgency pressure,
              credential harvesting, and embedded malicious links without remote data dispatch.
            </p>
          </div>

          {analysisResult && getRiskBadge(analysisResult.classification)}
        </div>

        {/* Preset Message Chips */}
        <div className="space-y-2.5">
          <label className="text-xs font-semibold text-charcoal flex items-center space-x-1.5">
            <Sparkles className="w-3.5 h-3.5 text-forest" />
            <span>Try a benchmark test scenario:</span>
          </label>
          <div className="flex flex-wrap gap-2">
            {PRESET_MESSAGES.map((preset, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => {
                  setInputText(preset.text);
                  handleAnalyze(preset.text);
                }}
                className="text-xs px-3.5 py-1.5 rounded-full bg-white/60 backdrop-blur-md border border-white/40 hover:bg-white/80 hover:border-forest/40 text-charcoal transition-colors"
              >
                {preset.name}
              </button>
            ))}
          </div>
        </div>

        {/* Input Text Area */}
        <div className="space-y-3">
          <textarea
            rows={3}
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            placeholder="Paste or type an SMS message to analyze for deceptive indicators..."
            className="w-full rounded-2xl bg-white/90 backdrop-blur-md border border-white/40 p-4 text-sm text-charcoal placeholder-charcoal-faint focus:outline-none focus:border-forest focus:ring-2 focus:ring-forest focus:bg-white transition font-mono leading-relaxed resize-y shadow-2xs"
          />

          <div className="flex items-center justify-between pt-1">
            <span className="text-[11px] text-charcoal-faint font-mono">
              {inputText.length} characters
            </span>
            <button
              type="button"
              disabled={isLoading || !inputText.trim()}
              onClick={() => handleAnalyze()}
              className="inline-flex items-center space-x-2 px-6 py-3 rounded-full bg-forest hover:bg-forest-hover disabled:opacity-50 text-white text-xs font-bold transition shadow-xs"
            >
              {isLoading ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Analyzing Message...</span>
                </>
              ) : (
                <>
                  <Send className="w-3.5 h-3.5" />
                  <span>Analyze Message</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Error Banner */}
        {errorMessage && (
          <div className="p-3.5 rounded-xl bg-rose-50 border border-rose-200 text-rose-800 text-xs">
            {errorMessage}
          </div>
        )}

        {/* Analysis Output Results */}
        {analysisResult && (
          <div className="space-y-6 pt-6 border-t border-border">
            {/* Scam Category Identification Card */}
            {analysisResult.scam_type && (
              <div className="p-4 rounded-xl bg-white/70 backdrop-blur-md border border-white/45 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs shadow-sm">
                <div className="flex items-center space-x-3">
                  <div className="p-2.5 rounded-lg bg-white/80 border border-white/40 shadow-2xs">
                    <Tag className="w-4 h-4 text-sage-600" />
                  </div>
                  <div>
                    <span className="text-[10px] uppercase font-mono font-bold text-charcoal-muted block">
                      Scam Typology Category
                    </span>
                    <div className="flex items-center space-x-2 mt-0.5">
                      <span
                        className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold border ${
                          SCAM_CATEGORY_COLORS[analysisResult.scam_type.category]?.bg || 'bg-white'
                        } ${SCAM_CATEGORY_COLORS[analysisResult.scam_type.category]?.text || 'text-charcoal'} ${
                          SCAM_CATEGORY_COLORS[analysisResult.scam_type.category]?.border || 'border-border'
                        }`}
                      >
                        {analysisResult.scam_type.label || analysisResult.scam_type.category}
                      </span>
                      {analysisResult.scam_type.confidence !== undefined && (
                        <span className="text-charcoal-muted font-mono text-[11px]">
                          Confidence: {(analysisResult.scam_type.confidence * 100).toFixed(0)}%
                        </span>
                      )}
                    </div>
                    {analysisResult.scam_type.explanation && (
                      <p className="text-[11px] text-charcoal-muted mt-1 leading-relaxed">
                        {analysisResult.scam_type.explanation}
                      </p>
                    )}
                  </div>
                </div>

                {analysisResult.scam_type.matched_patterns.length > 0 && (
                  <div className="flex flex-wrap gap-1 text-[10px] font-mono">
                    {analysisResult.scam_type.matched_patterns.map((pat, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-0.5 rounded-md bg-white/80 border border-white/40 text-charcoal"
                      >
                        {pat}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Deceptive Phrase Highlighting */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold text-charcoal uppercase tracking-wider">
                  Deceptive Phrase Highlighting
                </h3>
                <span className="text-[11px] text-charcoal-muted font-mono">
                  Exact character offsets mapped to original text
                </span>
              </div>

              <HighlightedMessage
                messageText={inputText}
                highlightedPhrases={analysisResult.highlighted_phrases}
              />
            </div>

            {/* Extracted Digital Entities */}
            {analysisResult.extracted_entities && (
              <div className="p-4 rounded-xl bg-white/70 backdrop-blur-md border border-white/45 space-y-3 text-xs shadow-sm">
                <div className="flex items-center justify-between border-b border-border pb-2">
                  <span className="font-bold text-charcoal flex items-center space-x-1.5">
                    <Layers className="w-4 h-4 text-sage-600" />
                    <span>Extracted Digital Entities & Contacts</span>
                  </span>
                  <span className="text-[10px] font-mono text-charcoal-muted">
                    Exact text & offset preservation
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  {/* URLs */}
                  <div className="space-y-1.5 p-3 rounded-lg bg-white/60 backdrop-blur-sm border border-white/40">
                    <span className="text-[11px] text-charcoal font-semibold flex items-center space-x-1">
                      <LinkIcon className="w-3.5 h-3.5 text-sage-600" />
                      <span>Embedded URLs ({analysisResult.extracted_entities.urls.length})</span>
                    </span>
                    {analysisResult.extracted_entities.urls.length > 0 ? (
                      <div className="space-y-1 pt-1">
                        {analysisResult.extracted_entities.urls.map((u, i) => (
                          <div
                            key={i}
                            className="px-2 py-1 rounded bg-white/80 border border-white/40 text-[11px] font-mono text-sage-800 break-all"
                          >
                            {u}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <span className="text-[11px] text-charcoal-muted italic block pt-1">None detected</span>
                    )}
                  </div>

                  {/* Phone Numbers */}
                  <div className="space-y-1.5 p-3 rounded-lg bg-white/60 backdrop-blur-sm border border-white/40">
                    <span className="text-[11px] text-charcoal font-semibold flex items-center space-x-1">
                      <Phone className="w-3.5 h-3.5 text-emerald-600" />
                      <span>Phone Numbers ({analysisResult.extracted_entities.phone_numbers.length})</span>
                    </span>
                    {analysisResult.extracted_entities.phone_numbers.length > 0 ? (
                      <div className="space-y-1 pt-1">
                        {analysisResult.extracted_entities.phone_numbers.map((p, i) => (
                          <div
                            key={i}
                            className="px-2 py-1 rounded bg-white/80 border border-white/40 text-[11px] font-mono text-emerald-800"
                          >
                            {p}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <span className="text-[11px] text-charcoal-muted italic block pt-1">None detected</span>
                    )}
                  </div>

                  {/* UPI Handles */}
                  <div className="space-y-1.5 p-3 rounded-lg bg-white/60 backdrop-blur-sm border border-white/40">
                    <span className="text-[11px] text-charcoal font-semibold flex items-center space-x-1">
                      <CreditCard className="w-3.5 h-3.5 text-amber-600" />
                      <span>UPI Handles ({analysisResult.extracted_entities.upi_ids.length})</span>
                    </span>
                    {analysisResult.extracted_entities.upi_ids.length > 0 ? (
                      <div className="space-y-1 pt-1">
                        {analysisResult.extracted_entities.upi_ids.map((up, i) => (
                          <div
                            key={i}
                            className="px-2 py-1 rounded bg-white/80 border border-white/40 text-[11px] font-mono text-amber-800"
                          >
                            {up}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <span className="text-[11px] text-charcoal-muted italic block pt-1">None detected</span>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* Embedded URL Analysis Results */}
            {analysisResult.embedded_url_analyses && analysisResult.embedded_url_analyses.length > 0 && (
              <div className="p-4 rounded-xl bg-white/70 backdrop-blur-md border border-white/45 space-y-3 text-xs shadow-sm">
                <div className="flex items-center justify-between border-b border-border pb-2">
                  <span className="font-bold text-charcoal flex items-center space-x-1.5">
                    <GlobeLock className="w-4 h-4 text-sage-600" />
                    <span>Embedded URL Structural Analysis</span>
                  </span>
                  <span className="text-[10px] text-charcoal-muted font-mono">
                    Passive structural inspection (zero network egress)
                  </span>
                </div>

                <div className="space-y-2">
                  {analysisResult.embedded_url_analyses.map((urlAnalysis, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-lg bg-white/60 backdrop-blur-sm border border-white/40 space-y-1.5"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-sage-900 text-xs font-semibold break-all">
                          {urlAnalysis.target_url}
                        </span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-white/80 text-charcoal border border-white/40 font-bold">
                          {urlAnalysis.classification}
                        </span>
                      </div>

                      {urlAnalysis.forensics && (
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-[11px] font-mono text-charcoal-muted pt-1">
                          <div>
                            <span className="text-charcoal-faint">Hostname: </span>
                            <span className="text-charcoal">{urlAnalysis.forensics.hostname || 'None'}</span>
                          </div>
                          <div>
                            <span className="text-charcoal-faint">Domain: </span>
                            <span className="text-charcoal">
                              {urlAnalysis.forensics.domain}.{urlAnalysis.forensics.tld}
                            </span>
                          </div>
                          <div>
                            <span className="text-charcoal-faint">Length: </span>
                            <span className="text-charcoal">{urlAnalysis.forensics.url_length} chars</span>
                          </div>
                          <div>
                            <span className="text-charcoal-faint">IP Host: </span>
                            <span className={urlAnalysis.forensics.has_ip_address ? 'text-rose-600 font-bold' : 'text-charcoal'}>
                              {urlAnalysis.forensics.has_ip_address ? 'YES (Suspicious)' : 'No'}
                            </span>
                          </div>
                        </div>
                      )}

                      {urlAnalysis.domain_intelligence && (
                        <div className="flex flex-wrap items-center gap-2 pt-1.5 border-t border-border-subtle/60 text-[10px] font-mono">
                          <span className="text-charcoal-muted font-medium">Domain Intel:</span>
                          {urlAnalysis.domain_intelligence.domain_age_days !== null && urlAnalysis.domain_intelligence.domain_age_days !== undefined ? (
                            <span
                              className={`px-1.5 py-0.5 rounded font-semibold ${
                                urlAnalysis.domain_intelligence.domain_age_days < 7
                                  ? 'bg-rose-100 text-rose-800 border border-rose-300'
                                  : urlAnalysis.domain_intelligence.domain_age_days <= 30
                                  ? 'bg-amber-100 text-amber-800 border border-amber-300'
                                  : 'bg-emerald-100 text-emerald-800 border border-emerald-300'
                              }`}
                            >
                              Age: {urlAnalysis.domain_intelligence.domain_age_days}d
                            </span>
                          ) : (
                            <span className="text-stone-500 bg-stone-100 px-1.5 py-0.5 rounded border border-stone-200">
                              Age: Unavailable
                            </span>
                          )}
                          {urlAnalysis.domain_intelligence.registrar && (
                            <span className="text-charcoal-muted truncate max-w-[160px]" title={urlAnalysis.domain_intelligence.registrar}>
                              Reg: {urlAnalysis.domain_intelligence.registrar}
                            </span>
                          )}
                          {urlAnalysis.domain_intelligence.tls_certificate_valid !== null && urlAnalysis.domain_intelligence.tls_certificate_valid !== undefined && (
                            <span className={urlAnalysis.domain_intelligence.tls_certificate_valid ? 'text-emerald-700 font-semibold' : 'text-rose-600 font-semibold'}>
                              {urlAnalysis.domain_intelligence.tls_certificate_valid ? '✓ TLS Handshake' : '✕ TLS Invalid'}
                            </span>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Dual Evidence Columns: ML Model + Social Engineering Heuristics */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Column A: ML Prediction */}
              <div className="p-4 rounded-xl bg-white/70 backdrop-blur-md border border-white/45 space-y-2.5 text-xs shadow-sm">
                <div className="flex items-center justify-between border-b border-border pb-2">
                  <span className="font-bold text-charcoal">Machine Learning Classification</span>
                  <span className="text-[10px] font-mono text-charcoal-muted">
                    {analysisResult.model_prediction?.model_name || 'TF-IDF + LogisticRegression'}
                  </span>
                </div>
                <div className="flex items-center justify-between py-1">
                  <span className="text-charcoal-muted">Predicted Classification:</span>
                  <span
                    className={`font-bold px-2 py-0.5 rounded ${
                      analysisResult.model_prediction?.is_scam
                        ? 'bg-rose-50 text-rose-700 border border-rose-200'
                        : 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                    }`}
                  >
                    {analysisResult.model_prediction?.is_scam ? 'SPAM / SCAM' : 'LEGITIMATE'}
                  </span>
                </div>
                {analysisResult.model_prediction?.confidence !== undefined && (
                  <div className="flex items-center justify-between py-1">
                    <span className="text-charcoal-muted">Model Probability:</span>
                    <span className="font-mono font-bold text-sage-900">
                      {(analysisResult.model_prediction.confidence * 100).toFixed(1)}%
                    </span>
                  </div>
                )}
              </div>

              {/* Column B: Heuristic Findings Summary */}
              <div className="p-4 rounded-xl bg-white/70 backdrop-blur-md border border-white/45 space-y-2.5 text-xs shadow-sm">
                <div className="flex items-center justify-between border-b border-border pb-2">
                  <span className="font-bold text-charcoal">Social Engineering Indicators</span>
                  <span className="text-[10px] font-mono text-charcoal-muted">7 Psychological Heuristics</span>
                </div>
                <div className="grid grid-cols-2 gap-1.5 text-[11px] pt-1">
                  <span className={analysisResult.social_engineering?.urgency ? 'text-amber-700 font-semibold' : 'text-charcoal-faint'}>
                    • Urgency: {analysisResult.social_engineering?.urgency ? 'DETECTED' : 'None'}
                  </span>
                  <span className={analysisResult.social_engineering?.threats ? 'text-rose-700 font-semibold' : 'text-charcoal-faint'}>
                    • Threats: {analysisResult.social_engineering?.threats ? 'DETECTED' : 'None'}
                  </span>
                  <span className={analysisResult.social_engineering?.impersonation ? 'text-indigo-700 font-semibold' : 'text-charcoal-faint'}>
                    • Impersonation: {analysisResult.social_engineering?.impersonation ? 'DETECTED' : 'None'}
                  </span>
                  <span className={analysisResult.social_engineering?.otp_requests ? 'text-red-700 font-semibold' : 'text-charcoal-faint'}>
                    • OTP Solicitation: {analysisResult.social_engineering?.otp_requests ? 'DETECTED' : 'None'}
                  </span>
                  <span className={analysisResult.social_engineering?.prize_bait ? 'text-emerald-700 font-semibold' : 'text-charcoal-faint'}>
                    • Prize Bait: {analysisResult.social_engineering?.prize_bait ? 'DETECTED' : 'None'}
                  </span>
                  <span className={analysisResult.social_engineering?.payment_demands ? 'text-amber-800 font-semibold' : 'text-charcoal-faint'}>
                    • Payment Demand: {analysisResult.social_engineering?.payment_demands ? 'DETECTED' : 'None'}
                  </span>
                </div>
                {analysisResult.social_engineering?.is_advisory_or_educational && (
                  <div className="mt-2 text-[11px] text-emerald-800 bg-emerald-50 border border-emerald-200 rounded-lg p-2 font-medium">
                    ✓ Verified Security Advisory / Educational Negation Pattern
                  </div>
                )}
              </div>
            </div>

            {/* Unified Evidence Hierarchy */}
            <UnifiedEvidenceViewer
              evidence={analysisResult.evidence}
              unifiedEvidence={analysisResult.unified_evidence}
              title="Unified Message Evidence Hierarchy"
            />

            {/* Recommendations & Reasoning */}
            <RecommendationCard
              structuredRecommendation={analysisResult.structured_recommendation}
              recommendations={analysisResult.recommendations}
              title="Actionable Security Recommendations"
            />
          </div>
        )}
      </div>

      {/* How It Works Section */}
      <div className="rounded-3xl bg-white/75 backdrop-blur-xl border border-white/35 p-6 md:p-8 space-y-4 shadow-2xl">
        <div className="flex items-center space-x-2.5 text-sage-900 font-bold text-base">
          <BookOpen className="w-5 h-5 text-sage-600" />
          <span>How Scam Message Detection Works</span>
        </div>
        <p className="text-xs text-charcoal-muted leading-relaxed">
          FraudLens uses a multi-stage offline analysis pipeline designed to protect users against psychological deception without risking their privacy.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 pt-2">
          <div className="p-4 rounded-xl bg-white/65 backdrop-blur-md border border-white/40 space-y-2 shadow-xs">
            <div className="w-6 h-6 rounded-full bg-sage-100 text-sage-800 font-bold text-xs flex items-center justify-center">
              1
            </div>
            <h4 className="font-bold text-charcoal text-xs">Text Normalization &amp; TF-IDF</h4>
            <p className="text-[11px] text-charcoal-muted leading-relaxed">
              Strips invisible zero-width characters and homoglyphic confusions, then computes term frequencies using scikit-learn TF-IDF matrices.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-white/65 backdrop-blur-md border border-white/40 space-y-2 shadow-xs">
            <div className="w-6 h-6 rounded-full bg-sage-100 text-sage-800 font-bold text-xs flex items-center justify-center">
              2
            </div>
            <h4 className="font-bold text-charcoal text-xs">Machine Learning Inference</h4>
            <p className="text-[11px] text-charcoal-muted leading-relaxed">
              Logistic Regression model evaluates deceptive text patterns trained on benchmark SMS fraud datasets to calculate scam probability.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-white/65 backdrop-blur-md border border-white/40 space-y-2 shadow-xs">
            <div className="w-6 h-6 rounded-full bg-sage-100 text-sage-800 font-bold text-xs flex items-center justify-center">
              3
            </div>
            <h4 className="font-bold text-charcoal text-xs">Behavioral Heuristics</h4>
            <p className="text-[11px] text-charcoal-muted leading-relaxed">
              Checks 7 social engineering categories (urgency traps, prize baits, OTP solicitation) while distinguishing legitimate defensive bank advisories.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-white/65 backdrop-blur-md border border-white/40 space-y-2 shadow-xs">
            <div className="w-6 h-6 rounded-full bg-sage-100 text-sage-800 font-bold text-xs flex items-center justify-center">
              4
            </div>
            <h4 className="font-bold text-charcoal text-xs">Entity &amp; Link Inspection</h4>
            <p className="text-[11px] text-charcoal-muted leading-relaxed">
              Extracts phone numbers, UPI handles, and embedded URLs, routing suspicious links into the Phishing URL engine with zero external network egress.
            </p>
          </div>
        </div>
      </div>
      </div>
    </div>
  );
};

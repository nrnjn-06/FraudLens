import React from 'react';
import type { StructuredSecurityRecommendation } from '../types/api';
import {
  ShieldCheck,
  AlertTriangle,
  ExternalLink,
  CheckCircle2,
  Building2,
  Info,
} from 'lucide-react';

interface RecommendationCardProps {
  structuredRecommendation?: StructuredSecurityRecommendation;
  recommendations?: string[];
  title?: string;
  className?: string;
}

export const RecommendationCard: React.FC<RecommendationCardProps> = ({
  structuredRecommendation,
  recommendations = [],
  title = 'Actionable Security Recommendations',
  className = '',
}) => {
  // If structured recommendation is available, render the enhanced 4-section layout
  if (structuredRecommendation && structuredRecommendation.detected_threat) {
    const rec = structuredRecommendation;

    return (
      <div
        className={`p-5 rounded-xl bg-white/70 backdrop-blur-md border border-white/45 text-xs space-y-4 shadow-sm ${className}`}
      >
        {/* Header with Title and Category Badge */}
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border pb-2.5">
          <div className="flex items-center space-x-2">
            <span className="font-bold text-charcoal uppercase tracking-wider text-xs">
              {rec.title || title}
            </span>
          </div>
          {rec.scam_category && (
            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-sage-100 text-sage-800 border border-sage-300">
              {rec.scam_category}
            </span>
          )}
        </div>

        {/* Section 1: What We Detected */}
        <div className="space-y-1">
          <span className="font-bold text-charcoal text-[11px] uppercase tracking-wider flex items-center gap-1.5 text-sage-900">
            <Info className="w-3.5 h-3.5 text-sage-600" />
            1. What We Detected
          </span>
          <p className="text-charcoal-muted leading-relaxed pl-5 text-[11.5px]">
            {rec.detected_threat}
          </p>
        </div>

        {/* Section 2: Why This Is Suspicious */}
        {rec.suspicious_reasons && rec.suspicious_reasons.length > 0 && (
          <div className="space-y-1.5">
            <span className="font-bold text-charcoal text-[11px] uppercase tracking-wider flex items-center gap-1.5 text-amber-900">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
              2. Why This Is Suspicious
            </span>
            <ul className="space-y-1 pl-5">
              {rec.suspicious_reasons.map((reason, idx) => (
                <li
                  key={idx}
                  className="flex items-start gap-2 text-charcoal-muted leading-relaxed text-[11px]"
                >
                  <span className="text-amber-500 font-bold leading-none mt-0.5">•</span>
                  <span>{reason}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Section 3: Safer Official Destination */}
        {rec.official_url_verified && rec.official_url ? (
          <div className="p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/25 space-y-2">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center space-x-1.5 text-emerald-800 font-bold text-xs">
                <ShieldCheck className="w-4 h-4 text-emerald-600 shrink-0" />
                <span>Verified Official Destination: {rec.organization_name}</span>
              </div>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-100 text-emerald-800 border border-emerald-300">
                Verified Registry
              </span>
            </div>

            <p className="text-[11px] text-charcoal-muted leading-relaxed">
              If you need to contact or access services from {rec.organization_name || 'this organization'},
              use this official, independently verified destination:
            </p>

            <div className="pt-1 flex items-center justify-between gap-2 bg-white/60 p-2 rounded border border-emerald-200">
              <a
                href={rec.official_url}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 font-semibold text-emerald-800 hover:text-emerald-900 hover:underline break-all text-xs"
              >
                <span>{rec.official_url}</span>
                <ExternalLink className="w-3.5 h-3.5 shrink-0 text-emerald-700" />
              </a>
            </div>

            {rec.official_url_source && (
              <p className="text-[10px] text-charcoal-muted italic pt-0.5">
                Source: {rec.official_url_source}
              </p>
            )}
          </div>
        ) : rec.is_impersonation_detected ? (
          <div className="p-3.5 rounded-lg bg-amber-500/10 border border-amber-500/25 space-y-1.5">
            <div className="flex items-center space-x-1.5 text-amber-900 font-bold text-xs">
              <Building2 className="w-4 h-4 text-amber-700 shrink-0" />
              <span>
                Ambiguous Brand Identity: {rec.organization_name || 'Unverified Organization'}
              </span>
            </div>
            <p className="text-[11px] text-charcoal-muted leading-relaxed">
              We detected possible impersonation of {rec.organization_name || 'an external brand'}, but
              FraudLens cannot independently verify their official website. Do not follow links from this
              untrusted communication. Navigate to the organization's official mobile application or search
              for their legitimate website through a trusted search engine.
            </p>
          </div>
        ) : null}

        {/* Section 4: What You Should Do (Action Steps) */}
        {rec.action_steps && rec.action_steps.length > 0 && (
          <div className="space-y-2 pt-1 border-t border-border/60">
            <span className="font-bold text-charcoal text-[11px] uppercase tracking-wider block">
              3. Recommended Action Steps
            </span>
            <ul className="space-y-1.5">
              {rec.action_steps.map((step, idx) => (
                <li
                  key={idx}
                  className="flex items-start gap-2 text-charcoal-muted leading-relaxed text-[11px]"
                >
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0 mt-0.5" />
                  <span>{step}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    );
  }

  // Fallback to legacy recommendations list
  if (!recommendations || recommendations.length === 0) {
    return null;
  }

  return (
    <div
      className={`p-4 rounded-xl bg-white/70 backdrop-blur-md border border-white/45 text-xs space-y-3 shadow-sm ${className}`}
    >
      <span className="font-bold text-charcoal uppercase tracking-wider block border-b border-border pb-2">
        {title}
      </span>
      <ul className="space-y-2 text-charcoal-muted">
        {recommendations.map((rec, i) => (
          <li key={i} className="flex items-start gap-2 leading-relaxed">
            <span className="text-emerald-600 font-bold leading-none mt-0.5">✓</span>
            <span>{rec}</span>
          </li>
        ))}
      </ul>
    </div>
  );
};

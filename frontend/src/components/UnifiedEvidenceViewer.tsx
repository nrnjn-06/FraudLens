import React from 'react';
import {
  ShieldAlert,
  Brain,
  Sliders,
  Info,
  Clock,
  Database,
} from 'lucide-react';
import type { UnifiedEvidenceItem, EvidenceCategory } from '../types/api';

interface UnifiedEvidenceViewerProps {
  evidence: string[];
  unifiedEvidence?: UnifiedEvidenceItem[];
  title?: string;
}

const getCategoryBadge = (category: EvidenceCategory) => {
  switch (category) {
    case 'CONFIRMED_THREAT_INTEL':
      return {
        label: 'External Threat Intel',
        icon: ShieldAlert,
        badgeClass: 'bg-rose-100 text-rose-900 border border-rose-300',
        dotClass: 'bg-rose-500',
      };
    case 'MODEL_PREDICTION':
      return {
        label: 'ML Model Inference',
        icon: Brain,
        badgeClass: 'bg-indigo-100 text-indigo-900 border border-indigo-300',
        dotClass: 'bg-indigo-500',
      };
    case 'HEURISTIC':
      return {
        label: 'Deterministic Heuristic',
        icon: Sliders,
        badgeClass: 'bg-amber-100 text-amber-900 border border-amber-300',
        dotClass: 'bg-amber-500',
      };
    case 'INFORMATIONAL':
    default:
      return {
        label: 'Informational',
        icon: Info,
        badgeClass: 'bg-sage-100 text-sage-900 border border-sage-300',
        dotClass: 'bg-sage-600',
      };
  }
};

const getSeverityClass = (sev: string) => {
  switch (sev) {
    case 'HIGH':
      return 'text-rose-700 font-bold bg-rose-50 border border-rose-200 px-1.5 py-0.5 rounded text-[10px]';
    case 'MEDIUM':
      return 'text-amber-700 font-semibold bg-amber-50 border border-amber-200 px-1.5 py-0.5 rounded text-[10px]';
    case 'LOW':
      return 'text-emerald-700 font-medium bg-emerald-50 border border-emerald-200 px-1.5 py-0.5 rounded text-[10px]';
    default:
      return 'text-charcoal-muted bg-surface-subtle border border-border px-1.5 py-0.5 rounded text-[10px]';
  }
};

export const UnifiedEvidenceViewer: React.FC<UnifiedEvidenceViewerProps> = ({
  evidence,
  unifiedEvidence,
  title = 'Multi-Source Evidence Hierarchy',
}) => {
  const hasUnified = unifiedEvidence && unifiedEvidence.length > 0;

  return (
    <div className="p-4 rounded-xl bg-white/70 backdrop-blur-md border border-white/45 space-y-3 shadow-sm">
      <div className="flex items-center justify-between border-b border-border pb-2.5">
        <span className="text-xs font-bold text-charcoal uppercase tracking-wider flex items-center gap-2">
          <Database className="w-4 h-4 text-sage-600" />
          {title}
        </span>
        {hasUnified && (
          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-white/80 border border-white/40 text-charcoal-muted">
            {unifiedEvidence.length} Structured Signal{unifiedEvidence.length > 1 ? 's' : ''}
          </span>
        )}
      </div>

      {hasUnified ? (
        <div className="space-y-2">
          {unifiedEvidence.map((item, idx) => {
            const config = getCategoryBadge(item.category);
            const Icon = config.icon;
            return (
              <div
                key={idx}
                className="p-3 rounded-lg bg-white/60 backdrop-blur-sm border border-white/40 text-xs space-y-1.5 transition-colors hover:border-sage-300 shadow-2xs"
              >
                <div className="flex flex-wrap items-center justify-between gap-1.5">
                  <div className="flex items-center gap-1.5">
                    <span
                      className={`inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded-full ${config.badgeClass}`}
                    >
                      <Icon className="w-3 h-3" />
                      {config.label}
                    </span>
                    <span className="text-[10px] font-mono text-charcoal-muted">
                      via <span className="text-charcoal font-semibold">{item.source}</span>
                    </span>
                  </div>

                  <div className="flex items-center gap-1.5 text-[10px] font-mono">
                    {item.is_cached && (
                      <span className="inline-flex items-center gap-0.5 text-sage-800 bg-sage-100 px-1.5 py-0.5 rounded-full border border-sage-200">
                        <Clock className="w-2.5 h-2.5 text-sage-600" />
                        Cached
                      </span>
                    )}
                    {item.status === 'STALE' && (
                      <span className="text-amber-800 bg-amber-100 px-1.5 py-0.5 rounded-full border border-amber-300">
                        Stale
                      </span>
                    )}
                    {item.status === 'UNAVAILABLE' && (
                      <span className="text-charcoal-muted bg-white/70 px-1.5 py-0.5 rounded-full border border-white/40">
                        Unavailable
                      </span>
                    )}
                    <span className={getSeverityClass(item.severity)}>
                      {item.severity}
                    </span>
                  </div>
                </div>

                <p className="text-charcoal text-xs leading-relaxed pl-0.5">
                  {item.description}
                </p>
              </div>
            );
          })}
        </div>
      ) : (
        <ul className="space-y-1.5 text-xs text-charcoal-muted">
          {evidence.map((ev, i) => (
            <li key={i} className="flex items-start gap-2">
              <span className="text-sage-600 font-mono text-sm leading-none">•</span>
              <span className="leading-relaxed text-charcoal">{ev}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};

import React, { useState } from 'react';
import type { HighlightedPhrase } from '../types/api';
import { AlertTriangle, Clock, ShieldAlert, Award, CreditCard, ExternalLink, KeyRound, Info } from 'lucide-react';

interface HighlightedMessageProps {
  messageText: string;
  highlightedPhrases?: HighlightedPhrase[];
  className?: string;
}

interface NormalizedHighlight {
  id: number;
  start: number;
  end: number;
  text: string;
  category: string;
  explanation: string;
}

const CATEGORY_CONFIG: Record<
  string,
  { label: string; bg: string; text: string; border: string; icon: React.FC<{ className?: string }> }
> = {
  urgency: {
    label: 'Artificial Urgency',
    bg: 'bg-amber-100 hover:bg-amber-200/90',
    text: 'text-amber-900',
    border: 'border-b-2 border-amber-500',
    icon: Clock,
  },
  threats: {
    label: 'Threat / Consequence',
    bg: 'bg-rose-100 hover:bg-rose-200/90',
    text: 'text-rose-900',
    border: 'border-b-2 border-rose-500',
    icon: AlertTriangle,
  },
  impersonation: {
    label: 'Impersonation Indicator',
    bg: 'bg-indigo-100 hover:bg-indigo-200/90',
    text: 'text-indigo-900',
    border: 'border-b-2 border-indigo-500',
    icon: ShieldAlert,
  },
  otp_requests: {
    label: 'Credential / OTP Request',
    bg: 'bg-red-100 hover:bg-red-200/90',
    text: 'text-red-950 font-medium',
    border: 'border-b-2 border-red-600',
    icon: KeyRound,
  },
  prize_bait: {
    label: 'Prize Bait',
    bg: 'bg-emerald-100 hover:bg-emerald-200/90',
    text: 'text-emerald-900',
    border: 'border-b-2 border-emerald-500',
    icon: Award,
  },
  payment_demands: {
    label: 'Payment Demand',
    bg: 'bg-yellow-100 hover:bg-yellow-200/90',
    text: 'text-yellow-900',
    border: 'border-b-2 border-yellow-500',
    icon: CreditCard,
  },
  link_click_pressure: {
    label: 'Link-Click Pressure',
    bg: 'bg-teal-100 hover:bg-teal-200/90',
    text: 'text-teal-900',
    border: 'border-b-2 border-teal-500',
    icon: ExternalLink,
  },
};

const DEFAULT_CONFIG = {
  label: 'Suspicious Indicator',
  bg: 'bg-orange-100 hover:bg-orange-200/90',
  text: 'text-orange-950',
  border: 'border-b-2 border-orange-500',
  icon: Info,
};

export const HighlightedMessage: React.FC<HighlightedMessageProps> = ({
  messageText,
  highlightedPhrases = [],
  className = '',
}) => {
  const [activeHighlightId, setActiveHighlightId] = useState<number | null>(null);

  if (!messageText) {
    return <div className="text-charcoal-muted italic text-sm">No message text provided.</div>;
  }

  // 1. Normalize and sanitize highlights
  const textLength = messageText.length;
  const normalizedHighlights: NormalizedHighlight[] = (highlightedPhrases || [])
    .map((h, idx) => {
      const s = Math.max(0, Math.min(h.start ?? h.start_idx ?? 0, textLength));
      const e = Math.max(0, Math.min(h.end ?? h.end_idx ?? 0, textLength));
      return {
        id: idx,
        start: s,
        end: e,
        text: h.text ?? h.phrase ?? messageText.slice(s, e),
        category: (h.category ?? 'suspicious_phrase').toLowerCase(),
        explanation: h.explanation ?? h.reason ?? 'Flagged as potential social engineering indicator.',
      };
    })
    .filter((h) => h.start < h.end);

  // 2. Build sorted unique cut points to partition the message into contiguous slices
  const cutPointsSet = new Set<number>([0, textLength]);
  normalizedHighlights.forEach((h) => {
    cutPointsSet.add(h.start);
    cutPointsSet.add(h.end);
  });
  const cutPoints = Array.from(cutPointsSet).sort((a, b) => a - b);

  // 3. Assemble text segments
  interface Segment {
    start: number;
    end: number;
    text: string;
    highlights: NormalizedHighlight[];
  }

  const segments: Segment[] = [];
  for (let i = 0; i < cutPoints.length - 1; i++) {
    const s = cutPoints[i];
    const e = cutPoints[i + 1];
    if (s < e) {
      const matching = normalizedHighlights.filter((h) => h.start <= s && e <= h.end);
      segments.push({
        start: s,
        end: e,
        text: messageText.slice(s, e),
        highlights: matching,
      });
    }
  }

  return (
    <div className={`space-y-4 ${className}`}>
      {/* Visual message container with highlighted spans */}
      <div className="relative rounded-xl bg-white/80 backdrop-blur-md border border-white/45 p-4 font-mono text-sm leading-relaxed whitespace-pre-wrap break-words text-charcoal shadow-inner">
        {segments.map((seg, idx) => {
          if (seg.highlights.length === 0) {
            return <React.Fragment key={idx}>{seg.text}</React.Fragment>;
          }

          // Pick primary highlight (prefer currently hovered one if matching)
          const primary =
            seg.highlights.find((h) => h.id === activeHighlightId) || seg.highlights[0];
          const cfg = CATEGORY_CONFIG[primary.category] || DEFAULT_CONFIG;
          const isFocused = seg.highlights.some((h) => h.id === activeHighlightId);

          return (
            <mark
              key={idx}
              role="mark"
              tabIndex={0}
              onMouseEnter={() => setActiveHighlightId(primary.id)}
              onMouseLeave={() => setActiveHighlightId(null)}
              onFocus={() => setActiveHighlightId(primary.id)}
              onBlur={() => setActiveHighlightId(null)}
              title={`[${cfg.label}] ${primary.explanation}`}
              className={`rounded px-1.5 py-0.5 mx-0.5 transition-all duration-150 cursor-pointer ${cfg.bg} ${cfg.text} ${cfg.border} ${
                isFocused ? 'ring-2 ring-sage-600 font-semibold shadow-sm' : ''
              }`}
            >
              {seg.text}
            </mark>
          );
        })}
      </div>

      {/* Structured Legend and Findings Breakdown */}
      {normalizedHighlights.length > 0 ? (
        <div className="space-y-2.5">
          <div className="flex items-center justify-between text-xs text-charcoal-muted font-medium">
            <span className="flex items-center space-x-1.5">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
              <span className="font-semibold text-charcoal">Flagged Suspicious Phrases ({normalizedHighlights.length})</span>
            </span>
            <span className="text-[11px] text-charcoal-faint">Hover phrase to highlight in message above</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5 text-xs">
            {normalizedHighlights.map((h) => {
              const cfg = CATEGORY_CONFIG[h.category] || DEFAULT_CONFIG;
              const IconComponent = cfg.icon;
              const isSelected = activeHighlightId === h.id;

              return (
                <div
                  key={h.id}
                  onMouseEnter={() => setActiveHighlightId(h.id)}
                  onMouseLeave={() => setActiveHighlightId(null)}
                  className={`p-3 rounded-xl border transition-all cursor-pointer ${
                    isSelected
                      ? 'bg-sage-50/90 backdrop-blur-sm border-sage-500 shadow-sm ring-1 ring-sage-400'
                      : 'bg-white/70 backdrop-blur-sm border border-white/40 hover:border-sage-400 hover:bg-white/85 shadow-2xs'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 mb-1.5">
                    <span
                      className={`inline-flex items-center space-x-1 px-2 py-0.5 rounded-full text-[10px] font-semibold border ${cfg.bg} ${cfg.text} ${cfg.border}`}
                    >
                      <IconComponent className="w-3 h-3" />
                      <span>{cfg.label}</span>
                    </span>
                    <span className="text-[10px] font-mono text-charcoal-faint">
                      [{h.start}..{h.end}]
                    </span>
                  </div>
                  <div className="font-mono text-charcoal font-semibold text-xs mb-1">
                    &ldquo;{h.text}&rdquo;
                  </div>
                  <div className="text-[11px] text-charcoal-muted font-sans leading-relaxed">
                    {h.explanation}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ) : (
        <div className="text-xs text-charcoal-muted flex items-center space-x-1.5 p-3 rounded-lg bg-white/60 backdrop-blur-sm border border-white/40">
          <Info className="w-4 h-4 text-sage-600" />
          <span>No suspicious social engineering phrases flagged in this message.</span>
        </div>
      )}
    </div>
  );
};

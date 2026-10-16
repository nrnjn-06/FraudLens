import React from 'react';
import { Clock, Globe2 } from 'lucide-react';
import type { ThreatIntelResult } from '../types/api';

interface ThreatIntelCardProps {
  threatIntel?: ThreatIntelResult;
}

export const ThreatIntelCard: React.FC<ThreatIntelCardProps> = ({ threatIntel }) => {
  if (!threatIntel) return null;

  const isConfigured = threatIntel.lookup_status !== 'UNCONFIGURED';

  const isFlagged = threatIntel.is_flagged;
  const isClean = threatIntel.lookup_status === 'CLEAN';
  const isRateLimited = threatIntel.lookup_status === 'RATE_LIMITED';

  const getStatusLabel = (status: string) => {
    switch (status) {
      case 'CLEAN':
        return 'Clean / Verified';
      case 'MATCH_FOUND':
        return 'Threat Flagged';
      case 'RATE_LIMITED':
        return 'Rate Limited';
      case 'SERVICE_UNAVAILABLE':
        return 'Unavailable';
      case 'UNCONFIGURED':
        return 'Local Standby';
      default:
        return status.replace(/STAGE_\d+(_[A-Z0-9]+)?/gi, '').trim() || 'Active';
    }
  };

  return (
    <div className="p-4 rounded-xl bg-white/70 backdrop-blur-md border border-white/45 space-y-3 shadow-sm">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-sage-900 flex items-center gap-1.5">
          <Globe2 className="w-4 h-4 text-sage-600" /> External Threat Intelligence Feeds
        </span>
        <div className="flex items-center gap-2">
          {threatIntel.is_cached && (
            <span className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded-full bg-sage-100 text-sage-800 border border-sage-200">
              <Clock className="w-2.5 h-2.5 text-sage-600" /> Cached
            </span>
          )}
          <span
            className={`text-[10px] font-medium px-2.5 py-0.5 rounded-full border ${
              isFlagged
                ? 'bg-rose-100 text-rose-800 border-rose-300'
                : isClean
                ? 'bg-emerald-100 text-emerald-800 border-emerald-300'
                : isRateLimited
                ? 'bg-amber-100 text-amber-800 border-amber-300'
                : 'bg-white/80 text-charcoal-muted border border-white/40'
            }`}
          >
            {getStatusLabel(threatIntel.lookup_status)}
          </span>
        </div>
      </div>

      <div className="text-xs space-y-2">
        <div className="flex justify-between text-charcoal-muted">
          <span>Provider Adapter:</span>
          <span className="font-mono text-charcoal font-medium">
            {threatIntel.provider_name || threatIntel.source}
          </span>
        </div>

        {isConfigured && (threatIntel.malicious_count !== undefined || threatIntel.harmless_count !== undefined) && (
          <div className="grid grid-cols-3 gap-2 p-2.5 rounded-lg bg-white/60 backdrop-blur-sm border border-white/40 text-center font-mono shadow-2xs">
            <div>
              <div className="text-[10px] text-rose-600 uppercase tracking-wider font-semibold">Malicious</div>
              <div className="text-base font-bold text-rose-700">{threatIntel.malicious_count ?? 0}</div>
            </div>
            <div>
              <div className="text-[10px] text-amber-600 uppercase tracking-wider font-semibold">Suspicious</div>
              <div className="text-base font-bold text-amber-700">{threatIntel.suspicious_count ?? 0}</div>
            </div>
            <div>
              <div className="text-[10px] text-emerald-600 uppercase tracking-wider font-semibold">Clean / Harmless</div>
              <div className="text-base font-bold text-emerald-700">{threatIntel.harmless_count ?? 0}</div>
            </div>
          </div>
        )}

        {threatIntel.details && (
          <p className="text-[11px] text-charcoal-muted leading-relaxed border-t border-border-subtle pt-2">
            {threatIntel.details}
          </p>
        )}

        <div className="text-[10px] text-charcoal-faint flex items-center justify-between pt-1 border-t border-border-subtle">
          <span>Lookup: {new Date(threatIntel.lookup_timestamp).toLocaleTimeString()}</span>
          <span className="italic font-medium">Offline by default • Zero body transmission</span>
        </div>
      </div>
    </div>
  );
};

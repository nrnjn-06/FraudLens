import React, { useState } from 'react';
import {
  Calendar,
  Clock,
  Compass,
  FileCheck2,
  Lock,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import type { DomainIntelligenceResult } from '../types/api';

interface DomainIntelligenceCardProps {
  domainIntel?: DomainIntelligenceResult;
}

export const DomainIntelligenceCard: React.FC<DomainIntelligenceCardProps> = ({ domainIntel }) => {
  const [showAllFindings, setShowAllFindings] = useState(false);

  if (!domainIntel) return null;

  const isNotApplicable = domainIntel.lookup_status === 'NOT_APPLICABLE';
  const isUnconfigured = domainIntel.lookup_status === 'UNCONFIGURED';
  const isTimedOut = domainIntel.lookup_status === 'TIMED_OUT';
  const isUnavailable = domainIntel.lookup_status === 'UNAVAILABLE';

  const ageDays = domainIntel.domain_age_days;

  const getAgeBadge = () => {
    if (isNotApplicable) {
      return {
        label: 'IP / Local Host (N/A)',
        classes: 'bg-stone-100 text-stone-700 border-stone-300',
        desc: 'Direct IP host or internal hostname. WHOIS/RDAP registration is not applicable.',
      };
    }
    if (ageDays === undefined || ageDays === null) {
      return {
        label: 'Registration Age Unavailable',
        classes: 'bg-stone-100 text-stone-600 border-stone-300',
        desc: 'Registry did not publish an authoritative creation date.',
      };
    }
    if (ageDays < 7) {
      return {
        label: `Critical: Very New (${ageDays}d old)`,
        classes: 'bg-rose-100 text-rose-800 border-rose-300 font-bold',
        desc: 'Registered less than 7 days ago. Extremely high correlation with disposable phishing campaigns.',
      };
    }
    if (ageDays <= 30) {
      return {
        label: `High Risk (${ageDays}d old)`,
        classes: 'bg-amber-100 text-amber-800 border-amber-300 font-semibold',
        desc: 'Registered within the last 30 days. Fresh domains are commonly leveraged in targeted fraud.',
      };
    }
    if (ageDays <= 90) {
      return {
        label: `Moderate Age (${ageDays}d old)`,
        classes: 'bg-amber-50 text-amber-700 border-amber-200',
        desc: 'Registered between 31 and 90 days ago.',
      };
    }
    if (ageDays <= 180) {
      return {
        label: `Mild Age (${ageDays}d old)`,
        classes: 'bg-stone-100 text-stone-700 border-stone-200',
        desc: 'Registered between 91 and 180 days ago.',
      };
    }
    return {
      label: `Established (${ageDays >= 365 ? `${(ageDays / 365).toFixed(1)} yrs` : `${ageDays}d`})`,
      classes: 'bg-emerald-100 text-emerald-800 border-emerald-300 font-medium',
      desc: 'Domain has over 180 days of active registration history.',
    };
  };

  const ageBadge = getAgeBadge();

  const formatDate = (isoStr?: string) => {
    if (!isoStr) return 'Not available';
    try {
      const d = new Date(isoStr);
      if (isNaN(d.getTime())) return isoStr;
      return d.toLocaleDateString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
      });
    } catch {
      return isoStr;
    }
  };

  const getStatusBadge = () => {
    if (isNotApplicable) return 'Not Applicable';
    if (isTimedOut) return 'Registry Timed Out';
    if (isUnconfigured) return 'Disabled / Standby';
    if (isUnavailable) return 'Registry Unavailable';
    if (domainIntel.rdap_available) return 'Authoritative RDAP';
    if (domainIntel.whois_available) return 'WHOIS Protocol';
    return domainIntel.lookup_status;
  };

  return (
    <div className="p-4 rounded-xl bg-white/70 backdrop-blur-md border border-white/45 space-y-3.5 shadow-sm">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-border-subtle pb-2.5">
        <span className="text-xs font-semibold text-sage-900 flex items-center gap-1.5">
          <Compass className="w-4 h-4 text-forest" />
          <span>Domain Intelligence &amp; Registration Forensics</span>
        </span>
        <div className="flex flex-wrap items-center gap-2">
          {domainIntel.is_cached && (
            <span className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded-full bg-sage-100 text-sage-800 border border-sage-200">
              <Clock className="w-2.5 h-2.5 text-sage-600" /> Cached
            </span>
          )}
          <span
            className={`text-[10px] font-mono px-2.5 py-0.5 rounded-full border ${ageBadge.classes}`}
          >
            {ageBadge.label}
          </span>
          <span className="text-[10px] font-medium px-2 py-0.5 rounded-full bg-white/80 text-charcoal border border-white/40">
            {getStatusBadge()}
          </span>
        </div>
      </div>

      {/* Grid of Domain Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-2.5">
        {/* Domain & Hostname */}
        <div className="p-2.5 rounded-lg bg-white/60 backdrop-blur-sm border border-white/40 text-xs space-y-1">
          <span className="text-[10px] text-charcoal-muted uppercase font-semibold flex items-center gap-1">
            <Server className="w-3 h-3 text-sage-600" /> Registrable Domain
          </span>
          <p className="font-mono font-bold text-charcoal truncate" title={domainIntel.domain}>
            {domainIntel.domain || 'N/A'}
          </p>
          <p className="text-[10px] font-mono text-charcoal-muted truncate" title={domainIntel.hostname}>
            Host: {domainIntel.hostname || 'N/A'}
          </p>
        </div>

        {/* Domain Age / Creation */}
        <div className="p-2.5 rounded-lg bg-white/60 backdrop-blur-sm border border-white/40 text-xs space-y-1">
          <span className="text-[10px] text-charcoal-muted uppercase font-semibold flex items-center gap-1">
            <Calendar className="w-3 h-3 text-sage-600" /> Registration Age
          </span>
          <p className="font-mono font-bold text-charcoal">
            {ageDays !== null && ageDays !== undefined ? `${ageDays} days` : 'Not Published'}
          </p>
          <p className="text-[10px] font-mono text-charcoal-muted truncate">
            Registered: {formatDate(domainIntel.domain_created_at)}
          </p>
        </div>

        {/* Registrar */}
        <div className="p-2.5 rounded-lg bg-white/60 backdrop-blur-sm border border-white/40 text-xs space-y-1">
          <span className="text-[10px] text-charcoal-muted uppercase font-semibold flex items-center gap-1">
            <FileCheck2 className="w-3 h-3 text-sage-600" /> Registrar
          </span>
          <p className="font-mono font-semibold text-charcoal truncate" title={domainIntel.registrar || 'Unknown'}>
            {domainIntel.registrar || 'Unknown / Hidden'}
          </p>
          <p className="text-[10px] font-mono text-charcoal-muted truncate">
            Expires: {formatDate(domainIntel.domain_expires_at)}
          </p>
        </div>

        {/* TLS Certificate Status */}
        <div className="p-2.5 rounded-lg bg-white/60 backdrop-blur-sm border border-white/40 text-xs space-y-1">
          <span className="text-[10px] text-charcoal-muted uppercase font-semibold flex items-center gap-1">
            <Lock className="w-3 h-3 text-sage-600" /> TLS Handshake
          </span>
          <p className="font-mono font-semibold flex items-center gap-1 truncate">
            {domainIntel.tls_certificate_valid === true ? (
              <span className="text-emerald-700 flex items-center gap-1 font-bold">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" /> Valid TLS
              </span>
            ) : domainIntel.tls_certificate_valid === false ? (
              <span className="text-rose-700 flex items-center gap-1 font-bold">
                <ShieldAlert className="w-3.5 h-3.5 text-rose-600" /> Invalid / Self-signed
              </span>
            ) : (
              <span className="text-charcoal-muted font-medium">Not Evaluated</span>
            )}
          </p>
          <p className="text-[10px] font-mono text-charcoal-muted truncate" title={domainIntel.tls_issuer || ''}>
            Issuer: {domainIntel.tls_issuer || 'N/A'}
          </p>
        </div>
      </div>

      {/* Subscore & Status details */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 p-2.5 rounded-lg bg-white/50 backdrop-blur-sm border border-white/30 text-xs">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-forest" />
          <span className="text-charcoal font-medium">Domain Intelligence Risk Weight:</span>
          <span className="font-mono font-bold text-forest">40% of URL Assessment</span>
        </div>
        {domainIntel.domain_intelligence_score !== null && domainIntel.domain_intelligence_score !== undefined && (
          <div className="flex items-center gap-2">
            <span className="text-charcoal-muted text-[11px]">Domain Risk Subscore:</span>
            <span
              className={`font-mono font-bold text-xs px-2 py-0.5 rounded ${
                domainIntel.domain_intelligence_score >= 0.65
                  ? 'bg-rose-100 text-rose-800 border border-rose-300'
                  : domainIntel.domain_intelligence_score >= 0.35
                  ? 'bg-amber-100 text-amber-800 border border-amber-300'
                  : 'bg-emerald-100 text-emerald-800 border border-emerald-300'
              }`}
            >
              {(domainIntel.domain_intelligence_score * 100).toFixed(0)}%
            </span>
          </div>
        )}
      </div>

      {/* Findings List */}
      {domainIntel.domain_intelligence_findings && domainIntel.domain_intelligence_findings.length > 0 && (
        <div className="space-y-1.5 pt-1">
          <span className="text-[11px] font-semibold text-charcoal uppercase tracking-wider block">
            Domain Intelligence Findings ({domainIntel.domain_intelligence_findings.length})
          </span>
          <div className="space-y-1 text-xs">
            {(showAllFindings
              ? domainIntel.domain_intelligence_findings
              : domainIntel.domain_intelligence_findings.slice(0, 3)
            ).map((finding, idx) => (
              <div
                key={idx}
                className="flex items-start gap-2 text-charcoal leading-relaxed p-2 rounded-lg bg-white/55 border border-white/35"
              >
                <span className="w-1.5 h-1.5 rounded-full bg-forest mt-1.5 shrink-0" />
                <span className="text-[11px] font-mono">{finding}</span>
              </div>
            ))}
          </div>

          {domainIntel.domain_intelligence_findings.length > 3 && (
            <button
              type="button"
              onClick={() => setShowAllFindings(!showAllFindings)}
              className="text-[11px] text-forest hover:text-forest-dark font-medium inline-flex items-center gap-1 pt-1"
            >
              {showAllFindings ? (
                <>
                  <ChevronUp className="w-3.5 h-3.5" /> Show fewer findings
                </>
              ) : (
                <>
                  <ChevronDown className="w-3.5 h-3.5" /> Show all {domainIntel.domain_intelligence_findings.length} findings
                </>
              )}
            </button>
          )}
        </div>
      )}

      {/* Educational Note & Egress Disclaimer */}
      <div className="p-3 rounded-lg bg-sage-50/70 border border-sage-200/80 text-[11px] text-sage-900 space-y-1 leading-relaxed">
        <p className="font-semibold text-sage-950">
          💡 Why Domain Age Matters:
        </p>
        <p className="text-sage-800">
          Over 70% of targeted phishing campaigns utilize domain names registered within days or weeks of an attack.
          Domains registered under 7 days receive critical alerts, while domains with long operating histories
          provide strong statistical resistance against disposable phishing tactics.
        </p>
      </div>

      <div className="text-[10px] text-charcoal-faint flex flex-col sm:flex-row items-start sm:items-center justify-between pt-1 border-t border-border-subtle gap-1">
        <span>Checked: {new Date(domainIntel.checked_at).toLocaleTimeString()}</span>
        <span className="italic font-medium">Safe RDAP/WHOIS lookup • Port 443 handshake only • Zero page content downloaded</span>
      </div>
    </div>
  );
};

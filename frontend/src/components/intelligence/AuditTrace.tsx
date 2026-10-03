import React from 'react';
import { CheckCircle2, ShieldAlert, AlertTriangle, Layers, Info } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { RiskAssessment } from '@/types';

interface AuditTraceProps {
  assessment: RiskAssessment | null | undefined;
  className?: string;
}

export const AuditTrace: React.FC<AuditTraceProps> = ({ assessment, className }) => {
  if (!assessment || !assessment.rule_ids || assessment.rule_ids.length === 0) {
    return (
      <div
        className={cn(
          'p-4 text-xs font-mono text-soc-muted bg-soc-surface rounded border border-soc-border',
          className,
        )}
      >
        No deterministic audit rules were triggered for this evaluation.
      </div>
    );
  }

  const getRuleDetails = (ruleId: string) => {
    switch (ruleId) {
      case 'KEV_CONFIRMED':
        return {
          icon: ShieldAlert,
          color: 'text-red-400 bg-red-500/10 border-red-500/30',
          title: 'CISA Known Exploited Vulnerabilities (KEV) Confirmed',
          description:
            'Vulnerability is actively cataloged in CISA KEV as known to be exploited in the wild.',
        };
      case 'SOURCE_APPLICABILITY_CONFLICT':
        return {
          icon: AlertTriangle,
          color: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
          title: 'Source Applicability Conflict Detected',
          description:
            'Vulnerability intelligence sources disagree on applicability or version ranges; escalated to review.',
        };
      case 'APPLICABILITY_LIKELY_AFFECTED':
        return {
          icon: CheckCircle2,
          color: 'text-rose-400 bg-rose-500/10 border-rose-500/30',
          title: 'Applicability Within Declared Version Range',
          description:
            'Installed component version matches affected version range provided by authoritative sources.',
        };
      case 'APPLICABILITY_LIKELY_NOT_AFFECTED':
        return {
          icon: CheckCircle2,
          color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
          title: 'Applicability Outside Declared Range',
          description:
            'Installed component version is confirmed outside the affected version range.',
        };
      case 'CVSS_CRITICAL':
      case 'CVSS_HIGH':
        return {
          icon: ShieldAlert,
          color: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
          title: 'Elevated CVSS Severity Metric',
          description: 'CVSS score indicates high or critical technical severity.',
        };
      case 'VERSION_DECLARED':
        return {
          icon: CheckCircle2,
          color: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
          title: 'Concrete Version Declared',
          description:
            'Component declares an exact pinned version allowing semantic version evaluation.',
        };
      case 'MATCH_COMPONENT_ONLY':
        return {
          icon: Layers,
          color: 'text-purple-400 bg-purple-500/10 border-purple-500/30',
          title: 'Component Identity Matched',
          description: 'Ecosystem and package name verified against vulnerability advisory record.',
        };
      default:
        return {
          icon: Info,
          color: 'text-slate-400 bg-slate-500/10 border-slate-500/30',
          title: `Rule: ${ruleId}`,
          description: 'Evaluated by Deterministic Risk Engine.',
        };
    }
  };

  return (
    <div className={cn('space-y-3', className)} data-testid="audit-trace">
      <div className="relative pl-6 before:content-[''] before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-soc-border">
        {assessment.rule_ids.map((ruleId, index) => {
          const detail = getRuleDetails(ruleId);
          const Icon = detail.icon;

          return (
            <div key={ruleId} className="relative mb-4 last:mb-0">
              {/* Dot */}
              <div
                className={cn(
                  'absolute -left-6 top-1 w-5 h-5 rounded-full border flex items-center justify-center bg-soc-bg',
                  detail.color,
                )}
              >
                <Icon className="w-3 h-3" aria-hidden="true" />
              </div>

              {/* Card */}
              <div className="p-3 rounded-lg bg-soc-surface border border-soc-border hover:border-soc-border-light transition-colors">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs font-semibold text-soc-primary">
                    {detail.title}
                  </span>
                  <span className="text-[11px] font-mono text-soc-muted px-1.5 py-0.5 rounded bg-soc-elevated">
                    Step {index + 1}: {ruleId}
                  </span>
                </div>
                <p className="text-xs text-soc-secondary mt-1 font-sans leading-relaxed">
                  {detail.description}
                </p>
              </div>
            </div>
          );
        })}
      </div>

      {assessment.rationale && (
        <div className="mt-4 p-3 rounded-md bg-soc-elevated/70 border border-soc-border text-xs text-soc-secondary">
          <strong className="text-soc-primary font-mono block mb-1">DETERMINISTIC RATIONALE</strong>
          <p className="font-sans leading-relaxed">{assessment.rationale}</p>
        </div>
      )}
    </div>
  );
};

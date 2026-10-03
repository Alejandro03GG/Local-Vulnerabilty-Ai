import React from 'react';
import { AlertTriangle, ShieldCheck } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { SourceConflict } from '@/types';
import { ApplicabilityBadge } from '../badges/ApplicabilityBadge';

interface ConflictPanelProps {
  conflicts: SourceConflict[];
  className?: string;
}

export const ConflictPanel: React.FC<ConflictPanelProps> = ({ conflicts, className }) => {
  if (!conflicts || conflicts.length === 0) {
    return (
      <div
        className={cn(
          'p-4 rounded-lg border border-emerald-500/20 bg-emerald-950/10 flex items-center gap-3 text-sm text-emerald-400',
          className,
        )}
        data-testid="no-source-conflicts"
      >
        <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" aria-hidden="true" />
        <div>
          <span className="font-semibold">No source conflicts detected.</span>
          <span className="text-xs text-soc-secondary block mt-0.5">
            All intelligence sources agree on version boundaries and applicability for this match.
          </span>
        </div>
      </div>
    );
  }

  return (
    <div className={cn('space-y-4', className)} data-testid="source-conflict-panel">
      {conflicts.map((conflict, idx) => (
        <div
          key={idx}
          className="rounded-lg border-2 border-amber-500/40 bg-amber-950/20 p-5 shadow-lg relative overflow-hidden"
        >
          <div className="absolute top-0 left-0 right-0 h-1 bg-amber-500/60" />

          <div className="flex items-start gap-3">
            <AlertTriangle className="w-6 h-6 text-amber-400 shrink-0 mt-0.5" aria-hidden="true" />
            <div className="flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs font-mono font-bold uppercase tracking-wider text-amber-400 px-2 py-0.5 rounded bg-amber-500/20 border border-amber-500/30">
                  SOURCE APPLICABILITY CONFLICT
                </span>
                <span className="text-xs font-mono text-soc-muted">
                  Field: <strong className="text-soc-primary">{conflict.field}</strong>
                </span>
                <span className="text-xs font-mono text-soc-muted">
                  Type: <strong className="text-soc-primary">{conflict.conflict_type}</strong>
                </span>
              </div>

              <h4 className="text-sm font-semibold text-soc-primary mt-2">
                Discrepancy Between Intelligence Sources
              </h4>

              {/* Source values breakdown */}
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 my-4">
                {conflict.sources.map((sourceName) => {
                  const val = conflict.values[sourceName];
                  const valStr =
                    typeof val === 'object' && val !== null
                      ? JSON.stringify(val)
                      : String(val ?? '—');
                  return (
                    <div
                      key={sourceName}
                      className="p-3 rounded bg-soc-surface border border-soc-border"
                    >
                      <div className="text-[11px] font-mono uppercase text-soc-secondary tracking-wider mb-1">
                        Source: <span className="text-soc-primary font-bold">{sourceName}</span>
                      </div>
                      <div className="mt-1">
                        {valStr === 'LIKELY_AFFECTED' ||
                        valStr === 'LIKELY_NOT_AFFECTED' ||
                        valStr === 'REQUIRES_REVIEW' ? (
                          <ApplicabilityBadge status={valStr} />
                        ) : (
                          <span className="font-mono text-xs text-soc-primary">{valStr}</span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Resolution and rationale */}
              <div className="mt-3 pt-3 border-t border-amber-500/20 flex flex-col gap-2">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono text-soc-secondary">
                    Consolidated Resolution:
                  </span>
                  <ApplicabilityBadge status={conflict.resolution} />
                </div>
                {conflict.rationale && (
                  <p className="text-xs text-soc-secondary leading-relaxed font-sans">
                    <strong className="text-soc-primary">Conflict Reason:</strong>{' '}
                    {conflict.rationale}
                  </p>
                )}
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
};

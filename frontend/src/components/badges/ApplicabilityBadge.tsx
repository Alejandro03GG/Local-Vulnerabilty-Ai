import React from 'react';
import { AlertTriangle, CheckCircle, HelpCircle, ShieldAlert, AlertCircle } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { ApplicabilityType } from '@/types';

interface ApplicabilityBadgeProps {
  status: ApplicabilityType | string;
  className?: string;
}

export const ApplicabilityBadge: React.FC<ApplicabilityBadgeProps> = ({ status, className }) => {
  const normalized = (status || '').toUpperCase();
  switch (normalized) {
    case 'LIKELY_AFFECTED':
      return (
        <span
          className={cn(
            'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-medium font-mono border',
            'bg-rose-500/10 text-rose-400 border-rose-500/30',
            className,
          )}
          data-testid="badge-likely-affected"
        >
          <AlertTriangle className="w-3.5 h-3.5 shrink-0 text-rose-400" aria-hidden="true" />
          <span>LIKELY_AFFECTED</span>
        </span>
      );

    case 'LIKELY_NOT_AFFECTED':
      return (
        <span
          className={cn(
            'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-medium font-mono border',
            'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
            className,
          )}
          data-testid="badge-likely-not-affected"
        >
          <CheckCircle className="w-3.5 h-3.5 shrink-0 text-emerald-400" aria-hidden="true" />
          <span>LIKELY_NOT_AFFECTED</span>
        </span>
      );

    case 'REQUIRES_REVIEW':
      return (
        <span
          className={cn(
            'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-medium font-mono border',
            'bg-amber-500/10 text-amber-400 border-amber-500/30 animate-pulse',
            className,
          )}
          data-testid="badge-requires-review"
        >
          <AlertCircle className="w-3.5 h-3.5 shrink-0 text-amber-400" aria-hidden="true" />
          <span>REQUIRES_REVIEW</span>
        </span>
      );

    case 'DETECTED':
      return (
        <span
          className={cn(
            'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-medium font-mono border',
            'bg-purple-500/10 text-purple-400 border-purple-500/30',
            className,
          )}
          data-testid="badge-detected"
        >
          <ShieldAlert className="w-3.5 h-3.5 shrink-0 text-purple-400" aria-hidden="true" />
          <span>DETECTED</span>
        </span>
      );

    case 'UNKNOWN':
    default:
      return (
        <span
          className={cn(
            'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-medium font-mono border',
            'bg-slate-500/10 text-slate-400 border-slate-500/30',
            className,
          )}
          data-testid="badge-unknown"
        >
          <HelpCircle className="w-3.5 h-3.5 shrink-0 text-slate-400" aria-hidden="true" />
          <span>{status || 'UNKNOWN'}</span>
        </span>
      );
  }
};

import React from 'react';
import { Loader2, CheckCircle2, XCircle, Clock } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useI18n } from '@/i18n';
import type { ScanStatus } from '@/types';

interface ScanStatusBadgeProps {
  status: ScanStatus | string;
  className?: string;
}

export const ScanStatusBadge: React.FC<ScanStatusBadgeProps> = ({ status, className }) => {
  const { t } = useI18n();

  switch (status.toLowerCase()) {
    case 'running':
      return (
        <span
          className={cn(
            'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-mono font-medium',
            'bg-blue-500/15 text-blue-400 border border-blue-500/30',
            className,
          )}
          data-testid="badge-status-running"
        >
          <Loader2 className="w-3.5 h-3.5 animate-spin text-blue-400" aria-hidden="true" />
          <span>{t('badges.scanStatus.running')}</span>
        </span>
      );

    case 'pending':
      return (
        <span
          className={cn(
            'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-mono font-medium',
            'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30',
            className,
          )}
          data-testid="badge-status-pending"
        >
          <Clock className="w-3.5 h-3.5 text-yellow-400" aria-hidden="true" />
          <span>{t('badges.scanStatus.pending')}</span>
        </span>
      );

    case 'completed':
      return (
        <span
          className={cn(
            'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-mono font-medium',
            'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30',
            className,
          )}
          data-testid="badge-status-completed"
        >
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" aria-hidden="true" />
          <span>{t('badges.scanStatus.completed')}</span>
        </span>
      );

    case 'failed':
      return (
        <span
          className={cn(
            'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-mono font-medium',
            'bg-rose-500/15 text-rose-400 border border-rose-500/30',
            className,
          )}
          data-testid="badge-status-failed"
        >
          <XCircle className="w-3.5 h-3.5 text-rose-400" aria-hidden="true" />
          <span>{t('badges.scanStatus.failed')}</span>
        </span>
      );

    default:
      return (
        <span
          className={cn(
            'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-mono font-medium',
            'bg-slate-500/15 text-slate-400 border border-slate-500/30',
            className,
          )}
        >
          <span>{status.toUpperCase()}</span>
        </span>
      );
  }
};

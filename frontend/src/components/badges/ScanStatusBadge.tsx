import React from 'react';
import { Loader2, CheckCircle2, XCircle, Clock } from 'lucide-react';
import { badgeClassName } from '@/lib/utils';
import { useI18n } from '@/i18n';
import type { ScanStatus } from '@/types';

interface ScanStatusBadgeProps {
  status: ScanStatus | string;
  className?: string;
}

export const ScanStatusBadge: React.FC<ScanStatusBadgeProps> = ({ status, className }) => {
  const { t } = useI18n();

  switch (status.toLowerCase()) {
    case 'running': {
      const label = t('badges.scanStatus.running');
      return (
        <span
          className={badgeClassName('bg-blue-500/15 text-blue-400 border-blue-500/30', className)}
          data-testid="badge-status-running"
          title={label}
        >
          <Loader2 className="w-3.5 h-3.5 shrink-0 mt-0.5 animate-spin text-blue-400" aria-hidden="true" />
          <span className="min-w-0">{label}</span>
        </span>
      );
    }
    case 'pending': {
      const label = t('badges.scanStatus.pending');
      return (
        <span
          className={badgeClassName(
            'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
            className,
          )}
          data-testid="badge-status-pending"
          title={label}
        >
          <Clock className="w-3.5 h-3.5 shrink-0 mt-0.5 text-yellow-400" aria-hidden="true" />
          <span className="min-w-0">{label}</span>
        </span>
      );
    }
    case 'completed': {
      const label = t('badges.scanStatus.completed');
      return (
        <span
          className={badgeClassName(
            'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
            className,
          )}
          data-testid="badge-status-completed"
          title={label}
        >
          <CheckCircle2
            className="w-3.5 h-3.5 shrink-0 mt-0.5 text-emerald-400"
            aria-hidden="true"
          />
          <span className="min-w-0">{label}</span>
        </span>
      );
    }
    case 'failed': {
      const label = t('badges.scanStatus.failed');
      return (
        <span
          className={badgeClassName('bg-rose-500/15 text-rose-400 border-rose-500/30', className)}
          data-testid="badge-status-failed"
          title={label}
        >
          <XCircle className="w-3.5 h-3.5 shrink-0 mt-0.5 text-rose-400" aria-hidden="true" />
          <span className="min-w-0">{label}</span>
        </span>
      );
    }
    default: {
      const label = status.toUpperCase();
      return (
        <span
          className={badgeClassName(
            'bg-slate-500/15 text-slate-400 border-slate-500/30',
            className,
          )}
          title={label}
        >
          <span className="min-w-0">{label}</span>
        </span>
      );
    }
  }
};

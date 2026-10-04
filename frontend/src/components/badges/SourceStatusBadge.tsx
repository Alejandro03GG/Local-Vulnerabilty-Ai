import React from 'react';
import { CheckCircle2, XCircle, Loader2, AlertTriangle, Clock } from 'lucide-react';
import { badgeClassName } from '@/lib/utils';
import { useI18n } from '@/i18n';
import type { SourceStatus } from '@/types';

interface SourceStatusBadgeProps {
  /** Preferred: backend source status. */
  status?: SourceStatus | string;
  /** Legacy boolean API used by older call sites/tests. */
  isAvailable?: boolean;
  className?: string;
}

export const SourceStatusBadge: React.FC<SourceStatusBadgeProps> = ({
  status,
  isAvailable,
  className,
}) => {
  const { t } = useI18n();
  const normalized = (status || '').toLowerCase();

  let kind: 'available' | 'syncing' | 'error' | 'neverSynced' | 'unavailable';
  if (status) {
    if (normalized === 'active') kind = 'available';
    else if (normalized === 'syncing') kind = 'syncing';
    else if (normalized === 'error') kind = 'error';
    else if (normalized === 'never_synced') kind = 'neverSynced';
    else kind = 'unavailable';
  } else if (typeof isAvailable === 'boolean') {
    kind = isAvailable ? 'available' : 'unavailable';
  } else {
    kind = 'unavailable';
  }

  if (kind === 'available') {
    const label = t('badges.sourceStatus.available');
    return (
      <span
        className={badgeClassName(
          'bg-emerald-500/15 text-emerald-400 border-emerald-500/30 shrink-0',
          className,
        )}
        data-testid="badge-source-available"
        title={label}
      >
        <CheckCircle2 className="w-3.5 h-3.5 shrink-0 text-emerald-400" aria-hidden="true" />
        <span className="min-w-0">{label}</span>
      </span>
    );
  }

  if (kind === 'syncing') {
    const label = t('badges.sourceStatus.syncing');
    return (
      <span
        className={badgeClassName(
          'bg-blue-500/15 text-blue-400 border-blue-500/30 shrink-0',
          className,
        )}
        data-testid="badge-source-syncing"
        title={label}
      >
        <Loader2 className="w-3.5 h-3.5 shrink-0 animate-spin text-blue-400" aria-hidden="true" />
        <span className="min-w-0">{label}</span>
      </span>
    );
  }

  if (kind === 'error') {
    const label = t('badges.sourceStatus.error');
    return (
      <span
        className={badgeClassName(
          'bg-rose-500/15 text-rose-400 border-rose-500/30 shrink-0',
          className,
        )}
        data-testid="badge-source-error"
        title={label}
      >
        <AlertTriangle className="w-3.5 h-3.5 shrink-0 text-rose-400" aria-hidden="true" />
        <span className="min-w-0">{label}</span>
      </span>
    );
  }

  if (kind === 'neverSynced') {
    const label = t('badges.sourceStatus.neverSynced');
    return (
      <span
        className={badgeClassName(
          'bg-slate-500/15 text-slate-400 border-slate-500/30 shrink-0',
          className,
        )}
        data-testid="badge-source-never-synced"
        title={label}
      >
        <Clock className="w-3.5 h-3.5 shrink-0 text-slate-400" aria-hidden="true" />
        <span className="min-w-0">{label}</span>
      </span>
    );
  }

  const label = t('badges.sourceStatus.unavailable');
  return (
    <span
      className={badgeClassName(
        'bg-rose-500/15 text-rose-400 border-rose-500/30 shrink-0',
        className,
      )}
      data-testid="badge-source-unavailable"
      title={label}
    >
      <XCircle className="w-3.5 h-3.5 shrink-0 text-rose-400" aria-hidden="true" />
      <span className="min-w-0">{label}</span>
    </span>
  );
};

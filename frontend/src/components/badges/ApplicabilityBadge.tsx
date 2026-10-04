import React from 'react';
import { AlertTriangle, CheckCircle, HelpCircle, ShieldAlert, AlertCircle } from 'lucide-react';
import { badgeClassName } from '@/lib/utils';
import { useI18n } from '@/i18n';
import type { ApplicabilityType } from '@/types';

interface ApplicabilityBadgeProps {
  status: ApplicabilityType | string;
  className?: string;
}

export const ApplicabilityBadge: React.FC<ApplicabilityBadgeProps> = ({ status, className }) => {
  const { t } = useI18n();
  const normalized = (status || '').toUpperCase();

  switch (normalized) {
    case 'LIKELY_AFFECTED': {
      const label = t('badges.applicability.likelyAffected');
      return (
        <span
          className={badgeClassName(
            'bg-rose-500/10 text-rose-400 border-rose-500/30',
            className,
          )}
          data-testid="badge-likely-affected"
          title={label}
        >
          <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5 text-rose-400" aria-hidden="true" />
          <span className="min-w-0">{label}</span>
        </span>
      );
    }
    case 'LIKELY_NOT_AFFECTED': {
      const label = t('badges.applicability.likelyNotAffected');
      return (
        <span
          className={badgeClassName(
            'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
            className,
          )}
          data-testid="badge-likely-not-affected"
          title={label}
        >
          <CheckCircle
            className="w-3.5 h-3.5 shrink-0 mt-0.5 text-emerald-400"
            aria-hidden="true"
          />
          <span className="min-w-0">{label}</span>
        </span>
      );
    }
    case 'REQUIRES_REVIEW': {
      const label = t('badges.applicability.requiresReview');
      return (
        <span
          className={badgeClassName(
            'bg-amber-500/10 text-amber-400 border-amber-500/30 animate-pulse',
            className,
          )}
          data-testid="badge-requires-review"
          title={label}
        >
          <AlertCircle className="w-3.5 h-3.5 shrink-0 mt-0.5 text-amber-400" aria-hidden="true" />
          <span className="min-w-0">{label}</span>
        </span>
      );
    }
    case 'DETECTED': {
      const label = t('badges.applicability.detected');
      return (
        <span
          className={badgeClassName(
            'bg-purple-500/10 text-purple-400 border-purple-500/30',
            className,
          )}
          data-testid="badge-detected"
          title={label}
        >
          <ShieldAlert
            className="w-3.5 h-3.5 shrink-0 mt-0.5 text-purple-400"
            aria-hidden="true"
          />
          <span className="min-w-0">{label}</span>
        </span>
      );
    }
    case 'UNKNOWN':
    default: {
      const label =
        !status || normalized === 'UNKNOWN' ? t('badges.applicability.unknown') : status;
      return (
        <span
          className={badgeClassName(
            'bg-slate-500/10 text-slate-400 border-slate-500/30',
            className,
          )}
          data-testid="badge-unknown"
          title={label}
        >
          <HelpCircle className="w-3.5 h-3.5 shrink-0 mt-0.5 text-slate-400" aria-hidden="true" />
          <span className="min-w-0">{label}</span>
        </span>
      );
    }
  }
};

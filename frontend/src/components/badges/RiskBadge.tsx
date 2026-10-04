import React from 'react';
import { Flame, AlertOctagon, AlertTriangle, Info } from 'lucide-react';
import { badgeClassName } from '@/lib/utils';
import { useI18n } from '@/i18n';
import type { RiskLevel } from '@/types';

interface RiskBadgeProps {
  level: RiskLevel | string;
  className?: string;
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({ level, className }) => {
  const { t } = useI18n();
  const normLevel = level ? level.toUpperCase() : 'UNKNOWN';

  switch (normLevel) {
    case 'CRITICAL': {
      const label = t('badges.risk.critical');
      return (
        <span
          className={badgeClassName(
            'bg-red-500/15 text-red-400 border-red-500/30 font-semibold',
            className,
          )}
          data-testid="badge-risk-critical"
          title={label}
        >
          <Flame className="w-3.5 h-3.5 shrink-0 mt-0.5 text-red-400" aria-hidden="true" />
          <span className="min-w-0">{label}</span>
        </span>
      );
    }
    case 'HIGH': {
      const label = t('badges.risk.high');
      return (
        <span
          className={badgeClassName(
            'bg-orange-500/15 text-orange-400 border-orange-500/30 font-semibold',
            className,
          )}
          data-testid="badge-risk-high"
          title={label}
        >
          <AlertOctagon
            className="w-3.5 h-3.5 shrink-0 mt-0.5 text-orange-400"
            aria-hidden="true"
          />
          <span className="min-w-0">{label}</span>
        </span>
      );
    }
    case 'MEDIUM': {
      const label = t('badges.risk.medium');
      return (
        <span
          className={badgeClassName(
            'bg-amber-500/15 text-amber-400 border-amber-500/30 font-semibold',
            className,
          )}
          data-testid="badge-risk-medium"
          title={label}
        >
          <AlertTriangle
            className="w-3.5 h-3.5 shrink-0 mt-0.5 text-amber-400"
            aria-hidden="true"
          />
          <span className="min-w-0">{label}</span>
        </span>
      );
    }
    case 'LOW': {
      const label = t('badges.risk.low');
      return (
        <span
          className={badgeClassName(
            'bg-blue-500/15 text-blue-400 border-blue-500/30 font-semibold',
            className,
          )}
          data-testid="badge-risk-low"
          title={label}
        >
          <Info className="w-3.5 h-3.5 shrink-0 mt-0.5 text-blue-400" aria-hidden="true" />
          <span className="min-w-0">{label}</span>
        </span>
      );
    }
    default: {
      const label = normLevel === 'UNKNOWN' ? t('badges.risk.unknown') : normLevel;
      return (
        <span
          className={badgeClassName(
            'bg-slate-500/15 text-slate-400 border-slate-500/30 font-semibold',
            className,
          )}
          data-testid="badge-risk-unknown"
          title={label}
        >
          <Info className="w-3.5 h-3.5 shrink-0 mt-0.5 text-slate-400" aria-hidden="true" />
          <span className="min-w-0">{label}</span>
        </span>
      );
    }
  }
};

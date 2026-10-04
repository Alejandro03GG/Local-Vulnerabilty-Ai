import React from 'react';
import { Flame, AlertOctagon, AlertTriangle, Info } from 'lucide-react';
import { cn } from '@/lib/utils';
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
    case 'CRITICAL':
      return (
        <span
          className={cn(
            'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-semibold font-mono border',
            'bg-red-500/15 text-red-400 border-red-500/30',
            className,
          )}
          data-testid="badge-risk-critical"
        >
          <Flame className="w-3.5 h-3.5 shrink-0 text-red-400" aria-hidden="true" />
          <span>{t('badges.risk.critical')}</span>
        </span>
      );

    case 'HIGH':
      return (
        <span
          className={cn(
            'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-semibold font-mono border',
            'bg-orange-500/15 text-orange-400 border-orange-500/30',
            className,
          )}
          data-testid="badge-risk-high"
        >
          <AlertOctagon className="w-3.5 h-3.5 shrink-0 text-orange-400" aria-hidden="true" />
          <span>{t('badges.risk.high')}</span>
        </span>
      );

    case 'MEDIUM':
      return (
        <span
          className={cn(
            'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-semibold font-mono border',
            'bg-amber-500/15 text-amber-400 border-amber-500/30',
            className,
          )}
          data-testid="badge-risk-medium"
        >
          <AlertTriangle className="w-3.5 h-3.5 shrink-0 text-amber-400" aria-hidden="true" />
          <span>{t('badges.risk.medium')}</span>
        </span>
      );

    case 'LOW':
      return (
        <span
          className={cn(
            'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-semibold font-mono border',
            'bg-blue-500/15 text-blue-400 border-blue-500/30',
            className,
          )}
          data-testid="badge-risk-low"
        >
          <Info className="w-3.5 h-3.5 shrink-0 text-blue-400" aria-hidden="true" />
          <span>{t('badges.risk.low')}</span>
        </span>
      );

    default:
      return (
        <span
          className={cn(
            'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-semibold font-mono border',
            'bg-slate-500/15 text-slate-400 border-slate-500/30',
            className,
          )}
          data-testid="badge-risk-unknown"
        >
          <Info className="w-3.5 h-3.5 shrink-0 text-slate-400" aria-hidden="true" />
          <span>{normLevel === 'UNKNOWN' ? t('badges.risk.unknown') : normLevel}</span>
        </span>
      );
  }
};

import React from 'react';
import { UserCheck, ShieldAlert } from 'lucide-react';
import { badgeClassName } from '@/lib/utils';
import { useI18n } from '@/i18n';

interface ReviewBadgeProps {
  requiresReview: boolean;
  className?: string;
}

export const ReviewBadge: React.FC<ReviewBadgeProps> = ({ requiresReview, className }) => {
  const { t } = useI18n();

  if (requiresReview) {
    const label = t('badges.review.required');
    return (
      <span
        className={badgeClassName(
          'bg-amber-500/15 text-amber-400 border-amber-500/30',
          className,
        )}
        data-testid="badge-review-required"
        title={label}
      >
        <ShieldAlert className="w-3.5 h-3.5 shrink-0 mt-0.5 text-amber-400" aria-hidden="true" />
        <span className="min-w-0">{label}</span>
      </span>
    );
  }

  const label = t('badges.review.notRequired');
  return (
    <span
      className={badgeClassName('bg-slate-500/10 text-slate-400 border-slate-500/20', className)}
      data-testid="badge-review-not-required"
      title={label}
    >
      <UserCheck className="w-3.5 h-3.5 shrink-0 mt-0.5 text-slate-400" aria-hidden="true" />
      <span className="min-w-0">{label}</span>
    </span>
  );
};

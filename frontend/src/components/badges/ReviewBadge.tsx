import React from 'react';
import { UserCheck, ShieldAlert } from 'lucide-react';
import { cn } from '@/lib/utils';

interface ReviewBadgeProps {
  requiresReview: boolean;
  className?: string;
}

export const ReviewBadge: React.FC<ReviewBadgeProps> = ({ requiresReview, className }) => {
  if (requiresReview) {
    return (
      <span
        className={cn(
          'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-mono font-medium',
          'bg-amber-500/15 text-amber-400 border border-amber-500/30',
          className,
        )}
        data-testid="badge-review-required"
      >
        <ShieldAlert className="w-3.5 h-3.5 text-amber-400" aria-hidden="true" />
        <span>HUMAN REVIEW REQUIRED</span>
      </span>
    );
  }

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-mono font-medium',
        'bg-slate-500/10 text-slate-400 border border-slate-500/20',
        className,
      )}
      data-testid="badge-review-not-required"
    >
      <UserCheck className="w-3.5 h-3.5 text-slate-400" aria-hidden="true" />
      <span>NO REVIEW NEEDED</span>
    </span>
  );
};

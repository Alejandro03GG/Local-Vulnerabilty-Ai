import React from 'react';
import { CheckCircle2, XCircle } from 'lucide-react';
import { cn } from '@/lib/utils';

interface SourceStatusBadgeProps {
  isAvailable: boolean;
  className?: string;
}

export const SourceStatusBadge: React.FC<SourceStatusBadgeProps> = ({ isAvailable, className }) => {
  if (isAvailable) {
    return (
      <span
        className={cn(
          'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-mono font-medium',
          'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30',
          className,
        )}
        data-testid="badge-source-available"
      >
        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" aria-hidden="true" />
        <span>AVAILABLE</span>
      </span>
    );
  }

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-mono font-medium',
        'bg-rose-500/15 text-rose-400 border border-rose-500/30',
        className,
      )}
      data-testid="badge-source-unavailable"
    >
      <XCircle className="w-3.5 h-3.5 text-rose-400" aria-hidden="true" />
      <span>UNAVAILABLE</span>
    </span>
  );
};

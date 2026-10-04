import React from 'react';
import { Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useI18n } from '@/i18n';

interface LoadingStateProps {
  message?: string;
  rows?: number;
  className?: string;
}

export const LoadingState: React.FC<LoadingStateProps> = ({ message, rows = 4, className }) => {
  const { t } = useI18n();

  return (
    <div
      className={cn('flex flex-col items-center justify-center p-12 text-center', className)}
      data-testid="loading-state"
    >
      <Loader2 className="w-8 h-8 animate-spin text-blue-500 mb-4" aria-hidden="true" />
      <p className="text-sm font-medium text-soc-secondary">
        {message ?? t('ui.loadingState.message')}
      </p>

      {rows > 0 && (
        <div className="w-full max-w-2xl mt-6 space-y-2.5">
          {Array.from({ length: rows }).map((_, i) => (
            <div
              key={i}
              className="h-8 bg-soc-elevated/60 animate-pulse rounded border border-soc-border/50 w-full"
              style={{ opacity: 1 - i * 0.15 }}
            />
          ))}
        </div>
      )}
    </div>
  );
};

export const TableSkeleton: React.FC<{ rows?: number; columns?: number }> = ({
  rows = 5,
  columns = 5,
}) => {
  return (
    <div className="w-full space-y-2 p-4">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex gap-4">
          {Array.from({ length: columns }).map((_, j) => (
            <div
              key={j}
              className="h-7 bg-soc-elevated/70 animate-pulse rounded border border-soc-border/40 flex-1"
            />
          ))}
        </div>
      ))}
    </div>
  );
};

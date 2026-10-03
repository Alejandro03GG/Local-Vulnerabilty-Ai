import React from 'react';
import { AlertOctagon, RotateCw, Copy, Check } from 'lucide-react';
import { cn } from '@/lib/utils';

interface ErrorStateProps {
  title?: string;
  description?: string;
  requestId?: string;
  onRetry?: () => void;
  className?: string;
}

export const ErrorState: React.FC<ErrorStateProps> = ({
  title = 'Unable to load vulnerability data',
  description = 'An error occurred while communicating with the local security engine.',
  requestId,
  onRetry,
  className,
}) => {
  const [copied, setCopied] = React.useState(false);

  const handleCopyRequestId = () => {
    if (requestId) {
      navigator.clipboard.writeText(requestId);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center p-8 text-center border border-red-500/20 bg-red-950/10 rounded-lg',
        className,
      )}
      data-testid="error-state"
    >
      <div className="w-12 h-12 rounded-full bg-red-500/10 flex items-center justify-center mb-4 text-red-400">
        <AlertOctagon className="w-6 h-6" aria-hidden="true" />
      </div>
      <h3 className="text-base font-semibold text-soc-primary mb-1">{title}</h3>
      <p className="text-sm text-soc-secondary max-w-md mb-4">{description}</p>

      {requestId && (
        <div className="flex items-center gap-2 mb-6 px-3 py-1.5 rounded bg-soc-elevated border border-soc-border text-xs font-mono text-soc-secondary">
          <span>Request ID:</span>
          <span className="text-soc-primary select-all">{requestId}</span>
          <button
            onClick={handleCopyRequestId}
            className="p-1 hover:text-white transition-colors"
            title="Copy Request ID"
            aria-label="Copy Request ID"
          >
            {copied ? (
              <Check className="w-3.5 h-3.5 text-emerald-400" />
            ) : (
              <Copy className="w-3.5 h-3.5" />
            )}
          </button>
        </div>
      )}

      {onRetry && (
        <button
          onClick={onRetry}
          className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-soc-elevated border border-soc-border-light rounded-md hover:bg-soc-highlight focus:outline-none focus:ring-2 focus:ring-blue-500 transition-colors"
        >
          <RotateCw className="w-4 h-4" aria-hidden="true" />
          <span>Retry Operation</span>
        </button>
      )}
    </div>
  );
};

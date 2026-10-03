import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { cn } from '@/lib/utils';

interface PageHeaderProps {
  title: string;
  subtitle?: string;
  backTo?: string;
  badge?: React.ReactNode;
  actions?: React.ReactNode;
  className?: string;
}

export const PageHeader: React.FC<PageHeaderProps> = ({
  title,
  subtitle,
  backTo,
  badge,
  actions,
  className,
}) => {
  const navigate = useNavigate();

  return (
    <div
      className={cn(
        'pb-5 mb-6 border-b border-soc-border flex flex-col md:flex-row md:items-center justify-between gap-4',
        className,
      )}
    >
      <div className="flex items-start gap-3">
        {backTo && (
          <button
            onClick={() => navigate(backTo)}
            className="p-1.5 rounded bg-soc-elevated border border-soc-border hover:bg-soc-highlight text-soc-secondary hover:text-white transition-colors mt-0.5"
            aria-label="Go Back"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
        )}
        <div>
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="text-xl font-bold tracking-tight text-soc-primary">{title}</h1>
            {badge && <div>{badge}</div>}
          </div>
          {subtitle && <p className="text-xs text-soc-secondary mt-1 font-sans">{subtitle}</p>}
        </div>
      </div>

      {actions && <div className="flex items-center gap-2.5 shrink-0">{actions}</div>}
    </div>
  );
};

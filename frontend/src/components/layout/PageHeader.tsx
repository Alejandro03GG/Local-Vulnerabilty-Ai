import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useI18n } from '@/i18n';

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
  const { t } = useI18n();

  return (
    <div
      className={cn(
        'pb-5 mb-6 border-b border-soc-border flex flex-col md:flex-row md:items-center justify-between gap-4',
        className,
      )}
    >
      <div className="flex items-start gap-3 min-w-0">
        {backTo && (
          <button
            onClick={() => navigate(backTo)}
            className="p-1.5 rounded bg-soc-elevated border border-soc-border hover:bg-soc-highlight text-soc-secondary hover:text-white transition-colors mt-0.5 shrink-0"
            aria-label={t('pageHeader.goBack')}
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
        )}
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="text-lg sm:text-xl font-bold tracking-tight text-soc-primary break-words">
              {title}
            </h1>
            {badge && <div className="min-w-0 max-w-full">{badge}</div>}
          </div>
          {subtitle && (
            <p className="text-xs text-soc-secondary mt-1 font-sans break-words">{subtitle}</p>
          )}
        </div>
      </div>

      {actions && (
        <div className="flex flex-wrap items-center gap-2.5 w-full md:w-auto md:shrink-0">
          {actions}
        </div>
      )}
    </div>
  );
};

import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { Search, Activity, ShieldCheck, AlertCircle, Menu } from 'lucide-react';
import { healthApi } from '@/services/api/health';
import { cn } from '@/lib/utils';
import { LanguageSwitcher, useI18n } from '@/i18n';

interface TopbarProps {
  onOpenCommandMenu: () => void;
  onToggleSidebar?: () => void;
}

export const Topbar: React.FC<TopbarProps> = ({ onOpenCommandMenu, onToggleSidebar }) => {
  const { t } = useI18n();
  const { data: health, isError } = useQuery({
    queryKey: ['health'],
    queryFn: healthApi.check,
    refetchInterval: 30000,
    retry: 1,
  });

  return (
    <header className="h-14 border-b border-soc-border bg-soc-surface/80 backdrop-blur px-4 flex items-center justify-between z-20">
      <div className="flex items-center gap-3">
        {onToggleSidebar && (
          <button
            onClick={onToggleSidebar}
            className="md:hidden p-1.5 rounded text-soc-secondary hover:text-soc-primary hover:bg-soc-elevated"
            aria-label={t('topbar.toggleNavigation')}
          >
            <Menu className="w-5 h-5" />
          </button>
        )}
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-blue-400" />
          <span className="text-xs font-mono font-medium text-soc-secondary hidden sm:inline">
            {t('topbar.consoleTitle')}
          </span>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <LanguageSwitcher />

        {/* Command Menu Search Trigger */}
        <button
          onClick={onOpenCommandMenu}
          className="flex items-center gap-3 px-3 py-1.5 rounded-md border border-soc-border bg-soc-elevated/70 text-soc-secondary hover:text-soc-primary hover:border-soc-border-light text-xs transition-colors"
          aria-label={t('topbar.openCommandMenu')}
        >
          <Search className="w-3.5 h-3.5 text-soc-muted" />
          <span className="hidden sm:inline">{t('topbar.quickJump')}</span>
          <kbd className="hidden sm:inline-flex items-center gap-0.5 px-1.5 py-0.5 text-[10px] font-mono text-soc-muted bg-soc-bg rounded border border-soc-border">
            ⌘K
          </kbd>
        </button>

        {/* Backend status indicator */}
        <div
          className={cn(
            'flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono border',
            isError
              ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
              : health?.status === 'ok' || health?.status === 'healthy'
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                : 'bg-slate-500/10 text-slate-400 border-slate-500/30',
          )}
          title={
            isError
              ? t('topbar.apiUnreachable')
              : t('topbar.engineStatus', {
                  version: health?.version || t('topbar.engineReady'),
                  database: health?.database || t('topbar.dbConnected'),
                })
          }
        >
          {isError ? (
            <>
              <AlertCircle className="w-3.5 h-3.5 text-rose-400" />
              <span className="hidden md:inline">{t('topbar.apiOffline')}</span>
            </>
          ) : (
            <>
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              <span className="hidden md:inline">{t('topbar.engineActive')}</span>
            </>
          )}
        </div>
      </div>
    </header>
  );
};

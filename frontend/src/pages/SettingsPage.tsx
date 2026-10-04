import React, { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Server, Moon, Monitor, ShieldCheck, Activity, Languages } from 'lucide-react';
import { PageHeader } from '@/components/layout/PageHeader';
import { healthApi } from '@/services/api/health';
import { LanguageSwitcher, useI18n } from '@/i18n';

export const SettingsPage: React.FC = () => {
  const { t } = useI18n();
  const [prefersReducedMotion, setPrefersReducedMotion] = useState(false);

  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    setPrefersReducedMotion(mediaQuery.matches);

    const handler = (e: MediaQueryListEvent) => setPrefersReducedMotion(e.matches);
    mediaQuery.addEventListener('change', handler);
    return () => mediaQuery.removeEventListener('change', handler);
  }, []);

  const { data: health, isLoading } = useQuery({
    queryKey: ['health'],
    queryFn: healthApi.check,
  });

  const apiBaseUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

  return (
    <div className="space-y-6" data-testid="settings-page">
      <PageHeader title={t('settings.title')} subtitle={t('settings.subtitle')} />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Environment & Backend Gateway */}
        <div className="p-5 rounded-lg border border-soc-border bg-soc-surface space-y-4">
          <div className="flex items-center gap-2 pb-2 border-b border-soc-border">
            <Server className="w-4 h-4 text-blue-400" />
            <h2 className="text-sm font-semibold text-soc-primary">{t('settings.gatewayTitle')}</h2>
          </div>

          <div className="space-y-3 text-xs font-mono">
            <div>
              <span className="text-soc-muted block mb-1">{t('settings.baseUrl')}</span>
              <div className="p-2.5 rounded bg-soc-elevated border border-soc-border text-soc-primary select-all">
                {apiBaseUrl}
              </div>
            </div>

            <div className="pt-2">
              <span className="text-soc-muted block mb-1">{t('settings.serviceStatus')}</span>
              <div className="flex items-center gap-2 text-soc-primary">
                {isLoading ? (
                  <span className="text-soc-muted">{t('settings.connecting')}</span>
                ) : health ? (
                  <span className="flex items-center gap-1.5 text-emerald-400">
                    <ShieldCheck className="w-4 h-4" />
                    {t('settings.operational', {
                      version: health.version || t('settings.versionUnavailable'),
                      database: health.database || t('settings.dbActive'),
                    })}
                  </span>
                ) : (
                  <span className="text-rose-400">{t('settings.unreachable')}</span>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Visual & Accessibility Options */}
        <div className="p-5 rounded-lg border border-soc-border bg-soc-surface space-y-4">
          <div className="flex items-center gap-2 pb-2 border-b border-soc-border">
            <Monitor className="w-4 h-4 text-purple-400" />
            <h2 className="text-sm font-semibold text-soc-primary">
              {t('settings.appearanceTitle')}
            </h2>
          </div>

          <div className="space-y-3 text-xs font-mono">
            <div className="flex items-center justify-between p-2.5 rounded bg-soc-elevated border border-soc-border">
              <div className="flex items-center gap-2">
                <Moon className="w-4 h-4 text-soc-muted" />
                <span className="text-soc-primary">{t('settings.themePalette')}</span>
              </div>
              <span className="text-blue-400 font-semibold">{t('settings.themeValue')}</span>
            </div>

            <div className="flex items-center justify-between p-2.5 rounded bg-soc-elevated border border-soc-border">
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-soc-muted" />
                <span className="text-soc-primary">{t('settings.reducedMotion')}</span>
              </div>
              <span
                className={
                  prefersReducedMotion ? 'text-emerald-400 font-semibold' : 'text-soc-muted'
                }
              >
                {prefersReducedMotion ? t('settings.reducedActive') : t('settings.standardMotion')}
              </span>
            </div>

            <div className="p-2.5 rounded bg-soc-elevated border border-soc-border space-y-2">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <Languages className="w-4 h-4 text-soc-muted" />
                  <span className="text-soc-primary">{t('settings.languageRow')}</span>
                </div>
                <LanguageSwitcher />
              </div>
              <p className="text-[11px] text-soc-muted font-sans">{t('settings.languageHint')}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

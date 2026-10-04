import React from 'react';
import { Languages } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useI18n } from './LanguageContext';
import { SUPPORTED_LOCALES, type Locale } from './types';

interface LanguageSwitcherProps {
  className?: string;
}

const LOCALE_LABELS: Record<Locale, string> = {
  en: 'EN',
  es: 'ES',
};

export const LanguageSwitcher: React.FC<LanguageSwitcherProps> = ({ className }) => {
  const { locale, setLocale, t } = useI18n();

  return (
    <div
      role="group"
      aria-label={t('language.label')}
      title={t('language.label')}
      className={cn(
        'inline-flex items-center gap-1 rounded-md border border-soc-border bg-soc-elevated/70 p-0.5 font-mono text-[11px]',
        className,
      )}
      data-testid="language-switcher"
    >
      <Languages className="w-3.5 h-3.5 text-soc-muted ml-1.5" aria-hidden="true" />
      {SUPPORTED_LOCALES.map((code) => {
        const isActive = code === locale;
        return (
          <button
            key={code}
            type="button"
            onClick={() => setLocale(code)}
            aria-pressed={isActive}
            aria-label={t(code === 'en' ? 'language.switchToEn' : 'language.switchToEs')}
            data-testid={`language-option-${code}`}
            className={cn(
              'px-2 py-1 rounded font-semibold tracking-wider transition-colors',
              isActive
                ? 'bg-blue-600/20 text-blue-300 border border-blue-500/30'
                : 'text-soc-secondary hover:text-soc-primary border border-transparent',
            )}
          >
            {LOCALE_LABELS[code]}
          </button>
        );
      })}
    </div>
  );
};

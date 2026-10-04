import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { en, type MessageKey } from './locales/en';
import { es } from './locales/es';
import { translate } from './translate';
import {
  DEFAULT_LOCALE,
  INTL_LOCALES,
  LOCALE_STORAGE_KEY,
  SUPPORTED_LOCALES,
  type Locale,
  type TranslateParams,
} from './types';

const dictionaries: Record<Locale, unknown> = { en, es };

export interface I18nContextValue {
  locale: Locale;
  /** BCP 47 tag for Intl formatting (en-US / es-ES). */
  dateLocale: string;
  setLocale: (locale: Locale) => void;
  t: (key: MessageKey, params?: TranslateParams) => string;
}

const I18nContext = createContext<I18nContextValue | null>(null);

function isLocale(value: unknown): value is Locale {
  return typeof value === 'string' && (SUPPORTED_LOCALES as readonly string[]).includes(value);
}

function readStoredLocale(): Locale {
  try {
    const stored = window.localStorage.getItem(LOCALE_STORAGE_KEY);
    return isLocale(stored) ? stored : DEFAULT_LOCALE;
  } catch {
    return DEFAULT_LOCALE;
  }
}

interface LanguageProviderProps {
  children: React.ReactNode;
}

export const LanguageProvider: React.FC<LanguageProviderProps> = ({ children }) => {
  const [locale, setLocaleState] = useState<Locale>(readStoredLocale);

  useEffect(() => {
    document.documentElement.lang = locale;
  }, [locale]);

  const setLocale = useCallback((next: Locale) => {
    setLocaleState(next);
    try {
      window.localStorage.setItem(LOCALE_STORAGE_KEY, next);
    } catch {
      // Storage may be unavailable (private mode); the in-memory locale still applies.
    }
  }, []);

  const value = useMemo<I18nContextValue>(
    () => ({
      locale,
      dateLocale: INTL_LOCALES[locale],
      setLocale,
      t: (key, params) => translate(dictionaries[locale], en, key, params),
    }),
    [locale, setLocale],
  );

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
};

// eslint-disable-next-line react-refresh/only-export-components
export function useI18n(): I18nContextValue {
  const context = useContext(I18nContext);
  if (!context) {
    throw new Error('useI18n must be used within a LanguageProvider');
  }
  return context;
}

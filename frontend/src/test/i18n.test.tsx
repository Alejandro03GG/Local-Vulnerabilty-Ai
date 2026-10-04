import { screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { render } from './renderWithLanguage';
import { LanguageSwitcher, LOCALE_STORAGE_KEY, interpolate, resolveKey, en, es } from '@/i18n';
import { RiskBadge } from '@/components/badges/RiskBadge';
import { ScanStatusBadge } from '@/components/badges/ScanStatusBadge';
import { ErrorState } from '@/components/ui/ErrorState';
import { formatDate } from '@/lib/utils';

function createMemoryStorage(): Storage {
  const store = new Map<string, string>();
  return {
    get length() {
      return store.size;
    },
    clear: () => store.clear(),
    getItem: (key) => store.get(key) ?? null,
    key: (index) => Array.from(store.keys())[index] ?? null,
    removeItem: (key) => {
      store.delete(key);
    },
    setItem: (key, value) => {
      store.set(key, String(value));
    },
  };
}

describe('i18n', () => {
  beforeEach(() => {
    // Node's experimental global localStorage can shadow jsdom's; use a deterministic in-memory one.
    Object.defineProperty(window, 'localStorage', {
      value: createMemoryStorage(),
      configurable: true,
    });
  });

  afterEach(() => {
    document.documentElement.lang = '';
  });

  it('defaults to English and sets the document language', () => {
    render(<ErrorState />);
    expect(screen.getByText('Unable to load vulnerability data')).toBeInTheDocument();
    expect(document.documentElement.lang).toBe('en');
  });

  it('switches to Spanish, persists the locale, and updates document language', () => {
    render(
      <>
        <LanguageSwitcher />
        <ErrorState />
        <RiskBadge level="critical" />
        <ScanStatusBadge status="running" />
      </>,
    );

    fireEvent.click(screen.getByTestId('language-option-es'));

    expect(
      screen.getByText('No se pudieron cargar los datos de vulnerabilidades'),
    ).toBeInTheDocument();
    expect(screen.getByText('CRÍTICO')).toBeInTheDocument();
    expect(screen.getByText('EN_EJECUCIÓN')).toBeInTheDocument();
    // data-testid stays based on the English status names
    expect(screen.getByTestId('badge-risk-critical')).toBeInTheDocument();
    expect(screen.getByTestId('badge-status-running')).toBeInTheDocument();
    expect(window.localStorage.getItem(LOCALE_STORAGE_KEY)).toBe('es');
    expect(document.documentElement.lang).toBe('es');

    fireEvent.click(screen.getByTestId('language-option-en'));
    expect(screen.getByText('CRITICAL')).toBeInTheDocument();
    expect(document.documentElement.lang).toBe('en');
  });

  it('restores the persisted locale on mount', () => {
    window.localStorage.setItem(LOCALE_STORAGE_KEY, 'es');
    render(<RiskBadge level="HIGH" />);
    expect(screen.getByText('ALTA')).toBeInTheDocument();
  });

  it('interpolates {param} placeholders and resolves nested keys', () => {
    expect(interpolate('No match for "{query}"', { query: 'abc' })).toBe('No match for "abc"');
    expect(interpolate('Keep {unknown}', { query: 'x' })).toBe('Keep {unknown}');
    expect(resolveKey(en, 'nav.dashboard')).toBe('Dashboard');
    expect(resolveKey(es, 'nav.dashboard')).toBe('Panel');
    expect(resolveKey(en, 'nav.missing')).toBeUndefined();
  });

  it('formats dates using the provided locale', () => {
    const iso = '2025-03-15T10:30:00Z';
    expect(formatDate(iso)).toBe(formatDate(iso, 'en-US'));
    expect(formatDate(iso, 'es-ES')).not.toBe(formatDate(iso, 'en-US'));
  });
});

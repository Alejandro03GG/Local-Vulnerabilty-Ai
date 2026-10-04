import type { ReactElement } from 'react';
import { render as rtlRender, type RenderOptions, type RenderResult } from '@testing-library/react';
import { LanguageProvider } from '@/i18n';

/** Drop-in replacement for RTL `render` that wraps the UI in the LanguageProvider (default `en`). */
export function render(ui: ReactElement, options?: Omit<RenderOptions, 'wrapper'>): RenderResult {
  return rtlRender(ui, { wrapper: LanguageProvider, ...options });
}

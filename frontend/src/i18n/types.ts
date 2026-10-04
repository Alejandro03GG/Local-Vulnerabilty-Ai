export type Locale = 'en' | 'es';

export const SUPPORTED_LOCALES: readonly Locale[] = ['en', 'es'];

export const DEFAULT_LOCALE: Locale = 'en';

export const LOCALE_STORAGE_KEY = 'vuln-ai-locale';

/** BCP 47 tags used for Intl date/number formatting. */
export const INTL_LOCALES: Record<Locale, string> = {
  en: 'en-US',
  es: 'es-ES',
};

/** Replaces every leaf string of T with `string`, preserving the object shape. */
export type MessageTree<T> = {
  [K in keyof T]: T[K] extends string ? string : MessageTree<T[K]>;
};

/** Union of all dotted paths pointing to leaf strings, e.g. `nav.dashboard`. */
export type MessagePath<T> = {
  [K in keyof T & string]: T[K] extends string ? K : `${K}.${MessagePath<T[K]>}`;
}[keyof T & string];

export type TranslateParams = Record<string, string | number>;

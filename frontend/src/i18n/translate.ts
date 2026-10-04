import type { TranslateParams } from './types';

type UnknownTree = { [key: string]: string | UnknownTree };

/** Resolves a dotted key (e.g. `nav.dashboard`) inside a nested message object. */
export function resolveKey(messages: unknown, key: string): string | undefined {
  let node: unknown = messages;
  for (const part of key.split('.')) {
    if (node === null || typeof node !== 'object') return undefined;
    node = (node as UnknownTree)[part];
  }
  return typeof node === 'string' ? node : undefined;
}

/** Replaces `{param}` placeholders; unknown placeholders are left untouched. */
export function interpolate(template: string, params?: TranslateParams): string {
  if (!params) return template;
  return template.replace(/\{(\w+)\}/g, (match, name: string) =>
    Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : match,
  );
}

/**
 * Translates `key` using `messages`, falling back to `fallback` and finally to the key itself
 * so a missing entry never renders an empty string.
 */
export function translate(
  messages: unknown,
  fallback: unknown,
  key: string,
  params?: TranslateParams,
): string {
  const template = resolveKey(messages, key) ?? resolveKey(fallback, key) ?? key;
  return interpolate(template, params);
}

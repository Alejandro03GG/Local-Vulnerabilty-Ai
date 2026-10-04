import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

export function formatDate(
  dateString: string | null | undefined,
  locale: string = 'en-US',
): string {
  if (!dateString) return '—';
  try {
    const d = new Date(dateString);
    if (isNaN(d.getTime())) return dateString;
    return new Intl.DateTimeFormat(locale, {
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    }).format(d);
  } catch {
    return dateString;
  }
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return '—';
  if (seconds < 1) return `${Math.round(seconds * 1000)}ms`;
  if (seconds < 60) return `${seconds.toFixed(2)}s`;
  const mins = Math.floor(seconds / 60);
  const remSecs = (seconds % 60).toFixed(0);
  return `${mins}m ${remSecs}s`;
}

export function formatPercent(value: number | null | undefined): string {
  if (value === null || value === undefined) return '—';
  return `${Math.round(value * 100)}%`;
}

/** Shared badge shell: never overflows parent cards/table cells. */
export function badgeClassName(...extra: Array<string | undefined>): string {
  return cn(
    'inline-flex max-w-full min-w-0 items-center gap-1 rounded border px-2 py-0.5 overflow-hidden',
    'text-[10px] sm:text-xs font-medium font-mono leading-snug',
    'whitespace-nowrap',
    ...extra,
  );
}


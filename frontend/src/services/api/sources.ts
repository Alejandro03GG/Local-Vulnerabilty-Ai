import { apiClient } from './client';
import type { Source, SourceStatus, SourceSyncResult } from '@/types';

/** True when the source is usable for scans (has completed sync or is actively syncing). */
export function isSourceAvailable(source: Pick<Source, 'status' | 'is_available'>): boolean {
  if (typeof source.is_available === 'boolean') {
    return source.is_available;
  }
  const status = (source.status || '').toLowerCase();
  return status === 'active' || status === 'syncing';
}

export function sourceStatusLabelKey(
  status: SourceStatus | string | undefined,
): 'available' | 'unavailable' | 'syncing' | 'error' | 'neverSynced' {
  switch ((status || '').toLowerCase()) {
    case 'active':
      return 'available';
    case 'syncing':
      return 'syncing';
    case 'error':
      return 'error';
    case 'never_synced':
      return 'neverSynced';
    default:
      return 'unavailable';
  }
}

export const sourcesApi = {
  list: () => apiClient<Source[]>('/api/v1/sources'),

  getStatus: (id: string) => apiClient<Source>(`/api/v1/sources/${id}/status`),

  sync: (id: string) =>
    apiClient<SourceSyncResult>(`/api/v1/sources/${id}/sync`, {
      method: 'POST',
    }),
};

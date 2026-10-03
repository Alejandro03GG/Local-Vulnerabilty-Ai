import { apiClient } from './client';
import type { Source, SourceSyncResult } from '@/types';

export const sourcesApi = {
  list: () => apiClient<Source[]>('/api/v1/sources'),

  getStatus: (id: string) => apiClient<Source>(`/api/v1/sources/${id}/status`),

  sync: (id: string) =>
    apiClient<SourceSyncResult>(`/api/v1/sources/${id}/sync`, {
      method: 'POST',
    }),
};

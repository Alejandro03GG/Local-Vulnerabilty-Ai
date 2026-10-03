import { apiClient } from './client';
import type { Match, PaginatedResponse } from '@/types';

export const matchesApi = {
  list: (scanId?: string, applicability?: string, page = 1, pageSize = 20) => {
    const params = new URLSearchParams({
      page: String(page),
      page_size: String(pageSize),
    });
    if (scanId) params.append('scan_id', scanId);
    if (applicability) params.append('applicability', applicability);
    return apiClient<PaginatedResponse<Match>>(`/api/v1/matches?${params.toString()}`);
  },

  get: (id: string) => apiClient<Match>(`/api/v1/matches/${id}`),

  reanalyze: (id: string) =>
    apiClient<Match>(`/api/v1/matches/${id}/reanalyze`, {
      method: 'POST',
    }),
};

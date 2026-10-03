import { apiClient } from './client';
import type { PaginatedResponse, Vulnerability } from '@/types';

export const vulnerabilitiesApi = {
  list: (sourceId?: string, page = 1, pageSize = 20) => {
    const params = new URLSearchParams({
      page: String(page),
      page_size: String(pageSize),
    });
    if (sourceId) params.append('source_id', sourceId);
    return apiClient<PaginatedResponse<Vulnerability>>(
      `/api/v1/vulnerabilities?${params.toString()}`,
    );
  },

  get: (id: string) => apiClient<Vulnerability>(`/api/v1/vulnerabilities/${id}`),
};

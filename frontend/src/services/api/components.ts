import { apiClient } from './client';
import type { DetectedComponent, PaginatedResponse } from '@/types';

export const componentsApi = {
  list: (projectId?: string, page = 1, pageSize = 20) => {
    const params = new URLSearchParams({
      page: String(page),
      page_size: String(pageSize),
    });
    if (projectId) params.append('project_id', projectId);
    return apiClient<PaginatedResponse<DetectedComponent>>(
      `/api/v1/components?${params.toString()}`,
    );
  },

  get: (id: string) => apiClient<DetectedComponent>(`/api/v1/components/${id}`),
};

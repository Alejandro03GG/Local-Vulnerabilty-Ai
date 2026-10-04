import { apiClient } from './client';
import type { DetectedComponent, PaginatedResponse } from '@/types';

export const componentsApi = {
  list: (projectId?: string, page = 1, pageSize = 20) => {
    const params = new URLSearchParams({
      page: String(page),
      page_size: String(pageSize),
    });
    if (projectId) {
      // Prefer nested project route; global list also accepts ?project_id=
      return apiClient<PaginatedResponse<DetectedComponent>>(
        `/api/v1/projects/${projectId}/components?${params.toString()}`,
      );
    }
    return apiClient<PaginatedResponse<DetectedComponent>>(
      `/api/v1/components?${params.toString()}`,
    );
  },

  get: (id: string) => apiClient<DetectedComponent>(`/api/v1/components/${id}`),
};

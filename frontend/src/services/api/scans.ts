import { apiClient } from './client';
import type { PaginatedResponse, Scan } from '@/types';

export const scansApi = {
  list: (projectId?: string, page = 1, pageSize = 20) => {
    const params = new URLSearchParams({
      page: String(page),
      page_size: String(pageSize),
    });
    if (projectId) params.append('project_id', projectId);
    return apiClient<PaginatedResponse<Scan>>(`/api/v1/scans?${params.toString()}`);
  },

  get: (id: string) => apiClient<Scan>(`/api/v1/scans/${id}`),

  runProjectScan: (projectId: string, runAi = true) =>
    apiClient<Scan>(`/api/v1/projects/${projectId}/scans?run_ai=${runAi}`, {
      method: 'POST',
    }),

  getExportUrl: (id: string, format: 'sarif' | 'cyclonedx' | 'spdx') =>
    `/api/v1/scans/${id}/export/${format}`,
};

import { apiClient } from './client';
import type { PaginatedResponse, Project, ProjectCreate, ProjectUpdate } from '@/types';

export const projectsApi = {
  list: (page = 1, pageSize = 20) =>
    apiClient<PaginatedResponse<Project>>(`/api/v1/projects?page=${page}&page_size=${pageSize}`),

  get: (id: string) => apiClient<Project>(`/api/v1/projects/${id}`),

  create: (data: ProjectCreate) =>
    apiClient<Project>('/api/v1/projects', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  update: (id: string, data: ProjectUpdate) =>
    apiClient<Project>(`/api/v1/projects/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  delete: (id: string) =>
    apiClient<void>(`/api/v1/projects/${id}`, {
      method: 'DELETE',
    }),
};

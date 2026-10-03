import { apiClient } from './client';
import type {
  ContainerComponent,
  ContainerImage,
  ContainerLayer,
  DockerfileScanResult,
  Match,
  PaginatedResponse,
} from '@/types';
import type { PolicyEvaluationResponse } from './policy';

export interface ContainerScanRequestPayload {
  archive_path: string;
  reference?: string;
  no_ai?: boolean;
  policy_id?: string;
}

export interface DockerfileScanPayload {
  content?: string;
  path?: string;
}

export const imagesApi = {
  list: (page = 1, pageSize = 20) => {
    const params = new URLSearchParams({
      page: String(page),
      page_size: String(pageSize),
    });
    return apiClient<PaginatedResponse<ContainerImage>>(`/api/v1/images?${params.toString()}`);
  },

  get: (id: string) => apiClient<ContainerImage>(`/api/v1/images/${id}`),

  getLayers: (id: string) => apiClient<ContainerLayer[]>(`/api/v1/images/${id}/layers`),

  getComponents: (id: string) => apiClient<ContainerComponent[]>(`/api/v1/images/${id}/components`),

  getVulnerabilities: (id: string) => apiClient<Match[]>(`/api/v1/images/${id}/vulnerabilities`),

  getDependencyGraph: (id: string) =>
    apiClient<{
      image_id: string;
      scan_id: string;
      nodes: Array<Record<string, unknown>>;
      edges: Array<Record<string, unknown>>;
    }>(`/api/v1/images/${id}/dependency-graph`),

  getPolicy: (id: string) => apiClient<PolicyEvaluationResponse>(`/api/v1/images/${id}/policy`),

  scanImage: (payload: ContainerScanRequestPayload) =>
    apiClient<ContainerImage>('/api/v1/images/scan', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  scanDockerfile: (payload: DockerfileScanPayload) =>
    apiClient<DockerfileScanResult>('/api/v1/container/dockerfile/scan', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
};

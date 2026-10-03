import { apiClient } from './client';
import type { HealthStatus } from '@/types';

export const healthApi = {
  check: () => apiClient<HealthStatus>('/health'),
};

/**
 * REST API client for Policy & Suppression management (Etapa 16).
 */

import { apiClient } from './client';

export type PolicyAction = 'ALLOW' | 'BLOCK' | 'REQUIRE_REVIEW' | 'ACCEPT_RISK';
export type PolicyStatus =
  'ALLOWED' | 'VIOLATION' | 'REQUIRES_REVIEW' | 'ACCEPTED_RISK' | 'SUPPRESSED';
export type SuppressionStatus = 'ACTIVE' | 'EXPIRED' | 'DISABLED';

export interface PolicyCondition {
  severity?: string | string[];
  risk_level?: string | string[];
  applicability?: string | string[];
  dependency_type?: string | string[];
  scope?: string | string[];
  ecosystem?: string | string[];
  package_name?: string | string[];
  package_version?: string;
  vulnerability_id?: string | string[];
  source?: string | string[];
  has_kev_evidence?: boolean;
  cvss_score?: number;
  cvss_comparator?: string;
  requires_human_review?: boolean;
  conflict_detected?: boolean;
  conflict_type?: string | string[];
}

export interface PolicyRule {
  id: string;
  description?: string;
  when: PolicyCondition;
  action: PolicyAction;
  reason?: string;
  enabled?: boolean;
  priority?: number;
}

export interface PolicyThresholds {
  fail_on: string[];
  fail_on_review: boolean;
}

export interface Policy {
  id: string;
  name: string;
  version: string;
  description: string;
  enabled: boolean;
  thresholds: PolicyThresholds;
  rules: PolicyRule[];
  default_action: PolicyAction;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface PolicyCreateRequest {
  name: string;
  version?: string;
  description?: string;
  enabled?: boolean;
  thresholds?: PolicyThresholds;
  rules?: PolicyRule[];
  default_action?: PolicyAction;
  metadata?: Record<string, unknown>;
}

export interface PolicyUpdateRequest {
  name?: string;
  description?: string;
  enabled?: boolean;
  thresholds?: PolicyThresholds;
  rules?: PolicyRule[];
  default_action?: PolicyAction;
  metadata?: Record<string, unknown>;
}

export interface PolicyValidateRequest {
  yaml_content?: string;
  policy?: PolicyCreateRequest;
}

export interface PolicyValidateResponse {
  valid: boolean;
  errors: string[];
  policy?: Policy;
}

export interface SuppressionMatchCriteria {
  vulnerability_id?: string;
  package_name?: string;
  ecosystem?: string;
  package_version?: string;
  finding_id?: string;
  project_id?: string;
}

export interface Suppression {
  id: string;
  project_id?: string | null;
  match_criteria: SuppressionMatchCriteria;
  reason: string;
  owner: string;
  reference: string;
  expires_at?: string | null;
  enabled: boolean;
  status: SuppressionStatus;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface SuppressionCreateRequest {
  project_id?: string;
  match_criteria?: SuppressionMatchCriteria;
  reason: string;
  owner: string;
  reference: string;
  expires_at?: string | null;
  enabled?: boolean;
}

export interface SuppressionUpdateRequest {
  reason?: string;
  owner?: string;
  reference?: string;
  expires_at?: string | null;
  enabled?: boolean;
  match_criteria?: SuppressionMatchCriteria;
}

export interface FindingEvaluation {
  finding_id: string;
  component_name: string;
  component_version: string;
  ecosystem: string;
  vulnerability_id: string;
  action: PolicyAction;
  status: PolicyStatus;
  matched_rules: string[];
  matched_suppression_id?: string | null;
  reason: string;
  is_violation: boolean;
  requires_human_review: boolean;
  audit_trace: Record<string, unknown>;
}

export interface PolicyEvaluationResponse {
  policy_id: string;
  policy_name: string;
  status: PolicyStatus;
  total_findings: number;
  allowed_count: number;
  violations_count: number;
  suppressed_count: number;
  accepted_risk_count: number;
  requires_review_count: number;
  has_violations: boolean;
  ci_exit_code: number;
  evaluations: FindingEvaluation[];
  violations: FindingEvaluation[];
  suppressions_applied: Array<Record<string, unknown>>;
  evaluated_at: string;
}

export interface PolicyEvaluateRequest {
  policy_id?: string;
  policy_content?: string;
}

export const policyApi = {
  listPolicies: (): Promise<Policy[]> => apiClient<Policy[]>('/api/v1/policies'),

  getPolicy: (id: string): Promise<Policy> => apiClient<Policy>(`/api/v1/policies/${id}`),

  createPolicy: (data: PolicyCreateRequest): Promise<Policy> =>
    apiClient<Policy>('/api/v1/policies', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  updatePolicy: (id: string, data: PolicyUpdateRequest): Promise<Policy> =>
    apiClient<Policy>(`/api/v1/policies/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  deletePolicy: (id: string): Promise<{ deleted: boolean }> =>
    apiClient<{ deleted: boolean }>(`/api/v1/policies/${id}`, {
      method: 'DELETE',
    }),

  validatePolicy: (data: PolicyValidateRequest): Promise<PolicyValidateResponse> =>
    apiClient<PolicyValidateResponse>('/api/v1/policies/validate', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  listSuppressions: (projectId?: string): Promise<Suppression[]> => {
    const query = projectId ? `?project_id=${encodeURIComponent(projectId)}` : '';
    return apiClient<Suppression[]>(`/api/v1/suppressions${query}`);
  },

  getSuppression: (id: string): Promise<Suppression> =>
    apiClient<Suppression>(`/api/v1/suppressions/${id}`),

  createSuppression: (data: SuppressionCreateRequest): Promise<Suppression> =>
    apiClient<Suppression>('/api/v1/suppressions', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  updateSuppression: (id: string, data: SuppressionUpdateRequest): Promise<Suppression> =>
    apiClient<Suppression>(`/api/v1/suppressions/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  deleteSuppression: (id: string): Promise<{ deleted: boolean }> =>
    apiClient<{ deleted: boolean }>(`/api/v1/suppressions/${id}`, {
      method: 'DELETE',
    }),

  getScanPolicy: (scanId: string): Promise<PolicyEvaluationResponse> =>
    apiClient<PolicyEvaluationResponse>(`/api/v1/scans/${scanId}/policy`),

  evaluateScanPolicy: (
    scanId: string,
    data: PolicyEvaluateRequest = {},
  ): Promise<PolicyEvaluationResponse> =>
    apiClient<PolicyEvaluationResponse>(`/api/v1/scans/${scanId}/policy/evaluate`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),
};

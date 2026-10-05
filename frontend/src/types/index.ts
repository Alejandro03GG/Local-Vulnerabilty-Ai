export type ApplicabilityType =
  | 'LIKELY_AFFECTED'
  | 'LIKELY_NOT_AFFECTED'
  | 'UNKNOWN'
  | 'DETECTED'
  | 'REQUIRES_REVIEW'
  | 'likely_affected'
  | 'likely_not_affected'
  | 'unknown'
  | 'detected'
  | 'requires_review';

export type RiskLevel =
  | 'LOW'
  | 'MEDIUM'
  | 'HIGH'
  | 'CRITICAL'
  | 'low'
  | 'medium'
  | 'high'
  | 'critical'
  | 'info'
  | 'unknown';

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed';

export interface PaginatedResponse<T> {
  items: T[];
  page: number;
  page_size: number;
  total: number;
}

export interface Project {
  id: string;
  name: string;
  path: string;
  created_at: string;
  updated_at: string;
  active_scans_count?: number;
}

export interface ProjectCreate {
  name: string;
  path: string;
}

export interface ProjectUpdate {
  name?: string;
  path?: string;
}

export interface ScanSummary {
  components: number;
  matches: number;
  kev_matches: number;
  requires_review: number;
}

export interface Scan {
  id: string;
  project_id: string;
  status: ScanStatus;
  components_found: number;
  vulnerabilities_found: number;
  kev_matches: number;
  duration_seconds: number | null;
  started_at: string | null;
  completed_at: string | null;
  error: string | null;
  summary?: ScanSummary;
  matches?: Match[];
}

export interface DetectedComponent {
  id: string;
  project_id: string;
  name: string;
  version: string;
  version_type: string;
  version_constraint?: string | null;
  source_file: string;
  ecosystem: string;
  component_type: string;
  is_direct?: boolean;
  dependency_type?: string;
  scope?: string;
  manifest_source?: string | null;
  lockfile_source?: string | null;
  parent_name?: string | null;
  dependency_path?: string[];
  detected_at: string;
}

export interface DependencyEdge {
  parent_name: string;
  parent_version?: string | null;
  child_name: string;
  child_version?: string | null;
  scope: string;
  requirement?: string | null;
}

export interface DependencyGraph {
  project_id: string;
  direct_count: number;
  transitive_count: number;
  edges_count: number;
  lockfiles_detected: string[];
  manifests_detected: string[];
  components: DetectedComponent[];
  edges: DependencyEdge[];
}

export interface Vulnerability {
  id: string;
  canonical_id?: string | null;
  cve_id?: string | null;
  source_id?: string | null;
  vendor_project?: string | null;
  product?: string | null;
  vulnerability_name?: string | null;
  short_description?: string | null;
  required_action?: string | null;
  date_added?: string | null;
  due_date?: string | null;
  known_ransomware_use?: string | null;
  cwes: string[];
  notes?: string | null;
  synced_at?: string | null;
}

export interface MatchEvidence {
  source_name: string;
  identifier: string;
  package_name: string;
  ecosystem: string;
  installed_version?: string | null;
  affected_range?: string | null;
  fixed_version?: string | null;
  status: string;
  evidence_type: string;
  details: string;
}

export interface SourceConflict {
  conflict_type: string;
  severity: string;
  field: string;
  sources: string[];
  identifiers: string[];
  values: Record<string, unknown>;
  resolution: string;
  rationale: string;
}

export interface AIAnalysis {
  provider: string;
  model: string;
  explanation: string;
  evidence: string[];
  contextual_findings: string[];
  requires_human_review: boolean;
  duration_seconds: number;
  tokens_used: number;
  analyzed_at: string;
}

export interface DecisionResult {
  provider: string;
  model: string;
  responses: Record<string, string>;
  decision_probabilities: Record<string, number>;
  applicability_probability: number;
  urgency_score: number;
  latency_seconds: number;
  timestamp: string;
}

export interface RiskAssessment {
  status: string;
  risk_level: RiskLevel;
  certainty: number;
  rationale: string;
  recommended_action: string;
  requires_human_review: boolean;
  rule_ids: string[];
  assessed_at: string;
}

export interface Match {
  id: string;
  scan_id: string;
  component_id: string;
  vulnerability_id: string;
  match_type: string;
  match_confidence: number;
  applicability: ApplicabilityType;
  evidence: string[];
  matched_at: string;
  component?: DetectedComponent | null;
  vulnerability?: Vulnerability | null;
  ai_analysis?: AIAnalysis | null;
  decision_result?: DecisionResult | null;
  risk_assessment?: RiskAssessment | null;
  structured_evidences: MatchEvidence[];
  conflicts: SourceConflict[];
}

export type SourceStatus = 'active' | 'syncing' | 'error' | 'never_synced' | 'disabled';

export interface Source {
  id: string;
  name: string;
  source_type: string;
  url?: string;
  /** Backend source lifecycle status (API contract). */
  status: SourceStatus | string;
  last_sync: string | null;
  record_count: number;
  last_error?: string | null;
  /** @deprecated Prefer `status`; kept for older mocks. */
  is_available?: boolean;
  error_message?: string | null;
}

export interface SourceSyncResult {
  source_id: string;
  source_name: string;
  success: boolean;
  records_processed: number;
  synced_at: string;
  error_message?: string | null;
}

export interface HealthStatus {
  status: string;
  database: string;
  version: string;
}

export interface ContainerLayer {
  id: string;
  layer_index: number;
  digest: string;
  size_bytes: number;
  media_type: string;
  command?: string | null;
}

export interface ContainerImage {
  id: string;
  scan_id: string;
  reference: string;
  digest?: string | null;
  architecture: string;
  os: string;
  os_family?: string | null;
  os_version?: string | null;
  os_codename?: string | null;
  source_type: string;
  source_path?: string | null;
  created_at: string;
  layer_count: number;
  layers: ContainerLayer[];
  metadata?: Record<string, unknown>;
  dockerfile_ast?: DockerfileScanResult | null;
}

export interface ContainerComponent {
  id: string;
  name: string;
  version?: string | null;
  ecosystem: string;
  component_type: string;
  layer_digest?: string | null;
  container_path?: string | null;
  stage?: string | null;
  package_manager?: string | null;
  is_direct: boolean;
}

export interface DockerfileScanResult {
  source_file: string;
  stages: Array<{
    index: number;
    name?: string | null;
    base_image?: string | null;
    is_runtime: boolean;
  }>;
  base_images: Array<{
    registry?: string | null;
    repository: string;
    tag?: string | null;
    digest?: string | null;
    stage_alias?: string | null;
    line_number: number;
  }>;
  package_installations: Array<Record<string, unknown>>;
  copied_files: Array<Record<string, unknown>>;
  dependency_manifests: string[];
}

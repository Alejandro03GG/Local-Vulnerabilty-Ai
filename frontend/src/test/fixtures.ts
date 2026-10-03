import type {
  Match,
  DetectedComponent,
  Vulnerability,
  SourceConflict,
  RiskAssessment,
  AIAnalysis,
  DecisionResult,
} from '@/types';

export const mockComponent: DetectedComponent = {
  id: 'comp-123',
  project_id: 'proj-456',
  name: 'urllib3',
  version: '2.31.0',
  version_type: 'exact',
  version_constraint: '==2.31.0',
  source_file: 'requirements.txt',
  ecosystem: 'PyPI',
  component_type: 'direct',
  detected_at: '2026-10-02T12:00:00Z',
};

export const mockVulnerability: Vulnerability = {
  id: 'vuln-789',
  cve_id: 'CVE-2024-37891',
  vendor_project: 'urllib3',
  product: 'urllib3',
  vulnerability_name: 'Proxy-Authorization Header Leak',
  short_description: 'urllib3 leaks Proxy-Authorization header during cross-origin redirect',
  required_action: 'Apply security update to >=2.32.0',
  date_added: '2026-06-15T00:00:00Z',
  due_date: '2026-07-15T00:00:00Z',
  known_ransomware_use: 'Known',
  cwes: ['CWE-200', 'CWE-522'],
  synced_at: '2026-10-01T00:00:00Z',
};

export const mockConflict: SourceConflict = {
  conflict_type: 'applicability',
  severity: 'high',
  field: 'applicability',
  sources: ['OSV', 'NVD'],
  identifiers: ['GHSA-34jh-p97j-mpxf', 'CVE-2024-37891'],
  values: {
    OSV: 'LIKELY_AFFECTED',
    NVD: 'LIKELY_NOT_AFFECTED',
  },
  resolution: 'REQUIRES_REVIEW',
  rationale: 'OSV indicates affected range [2.0, 2.32) while NVD cpe indicates range ends at 2.30.',
};

export const mockRiskAssessmentWithConflict: RiskAssessment = {
  status: 'assessed',
  risk_level: 'HIGH',
  certainty: 0.65,
  rationale: 'Conflict between sources requires human security analyst review.',
  recommended_action: 'Perform manual inspection of urllib3 proxy redirect implementation.',
  requires_human_review: true,
  rule_ids: ['SOURCE_APPLICABILITY_CONFLICT', 'KEV_CONFIRMED', 'VERSION_DECLARED'],
  assessed_at: '2026-10-02T12:05:00Z',
};

export const mockAIAnalysis: AIAnalysis = {
  provider: 'ollama',
  model: 'llama3:latest',
  explanation: 'Contextual review of repository shows urllib3 is used in external webhook handler.',
  evidence: ['Proxy-Authorization header usage in webhooks.py'],
  contextual_findings: ['Potential cross-origin redirect vulnerability exists in network stack.'],
  requires_human_review: true,
  duration_seconds: 1.25,
  tokens_used: 180,
  analyzed_at: '2026-10-02T12:05:02Z',
};

export const mockDecisionResult: DecisionResult = {
  provider: 'systemone',
  model: 'fast-infer',
  responses: {
    'Is the package exposed to untrusted input?': 'Yes, exposed via public endpoint.',
  },
  decision_probabilities: {
    applicable: 0.88,
    not_applicable: 0.12,
  },
  applicability_probability: 0.88,
  urgency_score: 7.5,
  latency_seconds: 0.12,
  timestamp: '2026-10-02T12:05:03Z',
};

export const mockConflictedMatch: Match = {
  id: 'match-conflict-001',
  scan_id: 'scan-001',
  component_id: 'comp-123',
  vulnerability_id: 'vuln-789',
  match_type: 'exact',
  match_confidence: 0.95,
  applicability: 'REQUIRES_REVIEW',
  evidence: ['OSV [2.0, 2.32) WITHIN', 'NVD [2.0, 2.30) OUTSIDE'],
  matched_at: '2026-10-02T12:00:00Z',
  component: mockComponent,
  vulnerability: mockVulnerability,
  ai_analysis: mockAIAnalysis,
  decision_result: mockDecisionResult,
  risk_assessment: mockRiskAssessmentWithConflict,
  structured_evidences: [
    {
      source_name: 'OSV',
      identifier: 'GHSA-34jh-p97j-mpxf',
      package_name: 'urllib3',
      ecosystem: 'PyPI',
      installed_version: '2.31.0',
      affected_range: '>=2.0, <2.32',
      fixed_version: '2.32.0',
      status: 'LIKELY_AFFECTED',
      evidence_type: 'range_confirmed',
      details: 'Installed version 2.31.0 falls within [2.0, 2.32)',
    },
    {
      source_name: 'NVD',
      identifier: 'CVE-2024-37891',
      package_name: 'urllib3',
      ecosystem: 'PyPI',
      installed_version: '2.31.0',
      affected_range: '<2.30.0',
      fixed_version: '2.30.0',
      status: 'LIKELY_NOT_AFFECTED',
      evidence_type: 'outside_range',
      details: 'Installed version 2.31.0 is greater than 2.30.0',
    },
  ],
  conflicts: [mockConflict],
};

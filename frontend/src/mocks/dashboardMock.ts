import type { Match, PaginatedResponse, Project, Scan, Source } from '@/types';

/**
 * Temporary dashboard demo feed while the local API is offline.
 * Enabled when VITE_DASHBOARD_MOCK=true (see frontend/.env).
 */
export const DASHBOARD_MOCK_ENABLED = import.meta.env.VITE_DASHBOARD_MOCK === 'true';

const NOW = Date.parse('2026-10-04T16:30:00.000Z');

function hoursAgo(hours: number): string {
  return new Date(NOW - hours * 60 * 60 * 1000).toISOString();
}

function daysAgo(days: number): string {
  return new Date(NOW - days * 24 * 60 * 60 * 1000).toISOString();
}

const PROJECTS: Project[] = [
  {
    id: 'proj-pay-api-001',
    name: 'payments-api',
    path: '/Users/secops/repos/payments-api',
    created_at: daysAgo(42),
    updated_at: hoursAgo(6),
    active_scans_count: 1,
  },
  {
    id: 'proj-edge-gw-002',
    name: 'edge-gateway',
    path: '/Users/secops/repos/edge-gateway',
    created_at: daysAgo(28),
    updated_at: hoursAgo(18),
    active_scans_count: 0,
  },
  {
    id: 'proj-mobile-003',
    name: 'mobile-bff',
    path: '/Users/secops/repos/mobile-bff',
    created_at: daysAgo(19),
    updated_at: daysAgo(1),
    active_scans_count: 0,
  },
  {
    id: 'proj-helm-004',
    name: 'infra-helm-charts',
    path: '/Users/secops/repos/infra-helm-charts',
    created_at: daysAgo(11),
    updated_at: hoursAgo(30),
    active_scans_count: 0,
  },
];

const SCANS: Scan[] = [
  {
    id: 'scan-a1b2c3d4-0001',
    project_id: 'proj-pay-api-001',
    status: 'running',
    components_found: 186,
    vulnerabilities_found: 24,
    kev_matches: 2,
    duration_seconds: null,
    started_at: hoursAgo(0.35),
    completed_at: null,
    error: null,
    summary: { components: 186, matches: 24, kev_matches: 2, requires_review: 5 },
  },
  {
    id: 'scan-e5f6a7b8-0002',
    project_id: 'proj-edge-gw-002',
    status: 'completed',
    components_found: 312,
    vulnerabilities_found: 41,
    kev_matches: 3,
    duration_seconds: 148.4,
    started_at: hoursAgo(6),
    completed_at: hoursAgo(5.95),
    error: null,
    summary: { components: 312, matches: 41, kev_matches: 3, requires_review: 8 },
  },
  {
    id: 'scan-c9d0e1f2-0003',
    project_id: 'proj-mobile-003',
    status: 'completed',
    components_found: 254,
    vulnerabilities_found: 19,
    kev_matches: 1,
    duration_seconds: 97.2,
    started_at: hoursAgo(22),
    completed_at: hoursAgo(21.97),
    error: null,
    summary: { components: 254, matches: 19, kev_matches: 1, requires_review: 3 },
  },
  {
    id: 'scan-33445566-0004',
    project_id: 'proj-helm-004',
    status: 'failed',
    components_found: 0,
    vulnerabilities_found: 0,
    kev_matches: 0,
    duration_seconds: 12.1,
    started_at: hoursAgo(30),
    completed_at: hoursAgo(29.99),
    error: 'Manifest parser could not resolve Chart.yaml dependency lock.',
    summary: { components: 0, matches: 0, kev_matches: 0, requires_review: 0 },
  },
  {
    id: 'scan-77889900-0005',
    project_id: 'proj-pay-api-001',
    status: 'completed',
    components_found: 179,
    vulnerabilities_found: 21,
    kev_matches: 2,
    duration_seconds: 121.8,
    started_at: daysAgo(2),
    completed_at: daysAgo(2),
    error: null,
    summary: { components: 179, matches: 21, kev_matches: 2, requires_review: 4 },
  },
];

function riskMatch(
  id: string,
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
  applicability: Match['applicability'],
  requiresHumanReview: boolean,
): Match {
  return {
    id,
    scan_id: 'scan-e5f6a7b8-0002',
    component_id: `comp-${id}`,
    vulnerability_id: `vuln-${id}`,
    match_type: 'version_range',
    match_confidence: 0.91,
    applicability,
    evidence: ['OSV range match'],
    matched_at: hoursAgo(6),
    structured_evidences: [],
    conflicts: [],
    risk_assessment: {
      status: 'assessed',
      risk_level: riskLevel,
      certainty: requiresHumanReview ? 0.62 : 0.9,
      rationale: 'Deterministic engine evaluation for dashboard mock posture.',
      recommended_action: requiresHumanReview
        ? 'Escalate to security analyst for source conflict review.'
        : 'Apply vendor fixed version and re-scan.',
      requires_human_review: requiresHumanReview,
      rule_ids: requiresHumanReview
        ? ['SOURCE_APPLICABILITY_CONFLICT', 'VERSION_DECLARED']
        : ['LIKELY_AFFECTED', 'VERSION_DECLARED'],
      assessed_at: hoursAgo(6),
    },
  };
}

/** Coherent risk posture used by the dashboard severity cards. */
const MATCHES: Match[] = [
  ...Array.from({ length: 3 }, (_, i) =>
    riskMatch(`crit-${i + 1}`, 'CRITICAL', 'LIKELY_AFFECTED', false),
  ),
  ...Array.from({ length: 7 }, (_, i) =>
    riskMatch(`high-${i + 1}`, 'HIGH', 'LIKELY_AFFECTED', i < 2),
  ),
  ...Array.from({ length: 14 }, (_, i) =>
    riskMatch(
      `med-${i + 1}`,
      'MEDIUM',
      i % 4 === 0 ? 'REQUIRES_REVIEW' : 'LIKELY_AFFECTED',
      i % 4 === 0,
    ),
  ),
  ...Array.from({ length: 22 }, (_, i) =>
    riskMatch(`low-${i + 1}`, 'LOW', 'LIKELY_NOT_AFFECTED', false),
  ),
  ...Array.from({ length: 5 }, (_, i) =>
    riskMatch(`rev-${i + 1}`, 'HIGH', 'REQUIRES_REVIEW', true),
  ),
];

const SOURCES: Source[] = [
  {
    id: 'src-osv',
    name: 'OSV',
    source_type: 'ecosystem',
    is_available: true,
    last_sync: hoursAgo(2),
    record_count: 218_450,
  },
  {
    id: 'src-nvd',
    name: 'NVD',
    source_type: 'cve',
    is_available: true,
    last_sync: hoursAgo(4),
    record_count: 264_120,
  },
  {
    id: 'src-kev',
    name: 'CISA KEV',
    source_type: 'kev',
    is_available: true,
    last_sync: hoursAgo(1),
    record_count: 1_286,
  },
  {
    id: 'src-ghsa',
    name: 'GitHub Advisory',
    source_type: 'ecosystem',
    is_available: false,
    last_sync: daysAgo(3),
    record_count: 42_010,
    error_message: 'Rate limit exceeded during last sync window.',
  },
];

function pageOf<T>(items: T[], page = 1, pageSize = items.length): PaginatedResponse<T> {
  return {
    items,
    page,
    page_size: pageSize,
    total: items.length,
  };
}

export interface DashboardMockBundle {
  projects: PaginatedResponse<Project>;
  scans: PaginatedResponse<Scan>;
  componentsTotal: number;
  vulnerabilitiesTotal: number;
  matches: PaginatedResponse<Match>;
  sources: Source[];
}

/**
 * Structured SecOps demo snapshot:
 * 4 projects, 5 recent scans (1 running), risk mix, 4 intel sources.
 */
export const dashboardMock: DashboardMockBundle = {
  projects: pageOf(PROJECTS, 1, 100),
  scans: pageOf(SCANS, 1, 5),
  componentsTotal: 1_284,
  vulnerabilitiesTotal: 45_210,
  matches: pageOf(MATCHES, 1, 100),
  sources: SOURCES,
};

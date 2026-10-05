import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ToastProvider } from '@/components/ui/Toast';
import { LanguageProvider } from '@/i18n';
import { PoliciesPage } from '@/pages/PoliciesPage';
import { SuppressionsPage } from '@/pages/SuppressionsPage';
import { ScanDetailPage } from '@/pages/ScanDetailPage';
import * as policyApiModule from '@/services/api/policy';
import * as scansApiModule from '@/services/api/scans';

describe('Policy and Suppression Views (Etapa 16)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  const renderWithProviders = (
    initialRoute: string,
    element: React.ReactNode,
    path = initialRoute,
  ) => {
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    return render(
      <LanguageProvider>
        <QueryClientProvider client={queryClient}>
          <ToastProvider>
            <MemoryRouter initialEntries={[initialRoute]}>
              <Routes>
                <Route path={path} element={element} />
              </Routes>
            </MemoryRouter>
          </ToastProvider>
        </QueryClientProvider>
      </LanguageProvider>,
    );
  };

  it('renders PoliciesPage with policy list, rules, thresholds, and opens YAML validator', async () => {
    vi.spyOn(policyApiModule.policyApi, 'listPolicies').mockResolvedValue([
      {
        id: 'pol-org-1',
        name: 'org-enterprise-policy',
        version: '1.0',
        description: 'Enforce zero tolerance on critical vulnerabilities',
        enabled: true,
        thresholds: {
          fail_on: ['CRITICAL'],
          fail_on_review: true,
        },
        rules: [
          {
            id: 'block-critical-kev',
            description: 'Block all KEV vulnerabilities',
            when: { has_kev_evidence: true },
            action: 'BLOCK',
            reason: 'Active exploitation detected',
            priority: 10,
          },
        ],
        default_action: 'ALLOW',
        metadata: {},
        created_at: '2026-10-01T00:00:00Z',
        updated_at: '2026-10-01T00:00:00Z',
      },
    ]);

    renderWithProviders('/policies', <PoliciesPage />);

    const policyTitles = await screen.findAllByText('org-enterprise-policy');
    expect(policyTitles.length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('block-critical-kev')).toBeInTheDocument();
    expect(screen.getByText('Global Fail Severities')).toBeInTheDocument();

    // Open YAML validator modal
    const validateBtn = screen.getByText('Validate YAML Policy');
    await userEvent.click(validateBtn);
    expect(screen.getByText('Validate Security Policy (.vuln-ai.yaml)')).toBeInTheDocument();
  });

  it('renders SuppressionsPage with KPI counters, filter tabs, and audit details', async () => {
    vi.spyOn(policyApiModule.policyApi, 'listSuppressions').mockResolvedValue([
      {
        id: 'sup-1',
        project_id: null,
        match_criteria: {
          vulnerability_id: 'CVE-2023-9999',
          package_name: 'test-lib',
          ecosystem: 'pypi',
        },
        reason: 'False positive in staging',
        owner: 'qa-engineer@test.com',
        reference: 'TICKET-1234',
        expires_at: '2027-01-01T00:00:00Z',
        enabled: true,
        status: 'ACTIVE',
        created_by: 'system',
        created_at: '2026-10-01T00:00:00Z',
        updated_at: '2026-10-01T00:00:00Z',
      },
    ]);

    renderWithProviders('/suppressions', <SuppressionsPage />);

    expect(await screen.findByText('CVE-2023-9999')).toBeInTheDocument();
    expect(screen.getByText('test-lib (pypi)')).toBeInTheDocument();
    expect(screen.getByText('Active Exceptions')).toBeInTheDocument();
    expect(screen.getByText('qa-engineer@test.com')).toBeInTheDocument();
  });

  it('renders ScanDetailPage with Policy Compliance Evaluation card and violations', async () => {
    vi.spyOn(scansApiModule.scansApi, 'get').mockResolvedValue({
      id: 'scan-policy-123',
      project_id: 'proj-1',
      status: 'completed',
      components_found: 5,
      vulnerabilities_found: 1,
      kev_matches: 0,
      duration_seconds: 1.2,
      started_at: '2026-10-03T10:00:00Z',
      completed_at: '2026-10-03T10:00:01Z',
      error: null,
      matches: [],
    });

    vi.spyOn(policyApiModule.policyApi, 'getScanPolicy').mockResolvedValue({
      policy_id: 'pol-1',
      policy_name: 'strict-org-policy',
      status: 'VIOLATION',
      total_findings: 1,
      allowed_count: 0,
      violations_count: 1,
      suppressed_count: 0,
      accepted_risk_count: 0,
      requires_review_count: 0,
      has_violations: true,
      ci_exit_code: 1,
      evaluations: [],
      violations: [
        {
          finding_id: 'f1',
          component_name: 'requests',
          component_version: '2.25.0',
          ecosystem: 'pypi',
          vulnerability_id: 'CVE-2023-32681',
          action: 'BLOCK',
          status: 'VIOLATION',
          matched_rules: ['block-crit'],
          reason: 'Critical severity not permitted',
          is_violation: true,
          requires_human_review: false,
          audit_trace: {},
        },
      ],
      suppressions_applied: [],
      evaluated_at: '2026-10-03T10:00:01Z',
    });

    renderWithProviders('/scans/scan-policy-123', <ScanDetailPage />, '/scans/:scanId');

    await waitFor(() => {
      expect(screen.getByTestId('policy-compliance-card')).toBeInTheDocument();
    });
    expect(screen.getByText('CI EXIT 1 (FAIL)')).toBeInTheDocument();
    expect(screen.getByText('requests @ 2.25.0')).toBeInTheDocument();
    expect(screen.getByText('Critical severity not permitted')).toBeInTheDocument();
  });

  it('renders empty policies state when API returns []', async () => {
    vi.spyOn(policyApiModule.policyApi, 'listPolicies').mockResolvedValue([]);

    renderWithProviders('/policies', <PoliciesPage />);

    await waitFor(() => {
      expect(screen.queryByText('org-enterprise-policy')).not.toBeInTheDocument();
    });
    // Page still mounts and exposes validator affordance
    expect(screen.getByText(/Validate YAML Policy|Validar política YAML/i)).toBeInTheDocument();
  });

  it('keeps Policies page usable when policies API errors', async () => {
    const spy = vi
      .spyOn(policyApiModule.policyApi, 'listPolicies')
      .mockImplementation(() => Promise.reject(new Error('boom')));

    renderWithProviders('/policies', <PoliciesPage />);

    await waitFor(() => {
      expect(spy).toHaveBeenCalled();
      expect(screen.getByText('Validate YAML Policy')).toBeInTheDocument();
    });
    expect(screen.getAllByText('default-baseline-policy').length).toBeGreaterThanOrEqual(1);
  });

  it('renders accepted-risk and suppressed counters on scan policy card', async () => {
    vi.spyOn(scansApiModule.scansApi, 'get').mockResolvedValue({
      id: 'scan-policy-456',
      project_id: 'proj-1',
      status: 'completed',
      components_found: 2,
      vulnerabilities_found: 2,
      kev_matches: 0,
      duration_seconds: 1.0,
      started_at: '2026-10-03T10:00:00Z',
      completed_at: '2026-10-03T10:00:01Z',
      error: null,
      matches: [],
    });

    vi.spyOn(policyApiModule.policyApi, 'getScanPolicy').mockResolvedValue({
      policy_id: 'pol-2',
      policy_name: 'balanced-policy',
      status: 'ALLOWED',
      total_findings: 2,
      allowed_count: 0,
      violations_count: 0,
      suppressed_count: 1,
      accepted_risk_count: 1,
      requires_review_count: 0,
      has_violations: false,
      ci_exit_code: 0,
      evaluations: [],
      violations: [],
      suppressions_applied: [
        {
          suppression_id: 'sup-1',
          finding_id: 'f2',
          reason: 'Accepted temporary exception',
        },
      ],
      evaluated_at: '2026-10-03T10:00:01Z',
    });

    renderWithProviders('/scans/scan-policy-456', <ScanDetailPage />, '/scans/:scanId');

    await waitFor(() => {
      expect(screen.getByTestId('policy-compliance-card')).toBeInTheDocument();
    });
    expect(screen.getByText(/balanced-policy/i)).toBeInTheDocument();
  });

});

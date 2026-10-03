import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ToastProvider } from '@/components/ui/Toast';
import { ProjectDetailPage } from '@/pages/ProjectDetailPage';
import { ScanDetailPage } from '@/pages/ScanDetailPage';
import { VulnerabilityDetailPage } from '@/pages/VulnerabilityDetailPage';
import * as projectsApiModule from '@/services/api/projects';
import * as scansApiModule from '@/services/api/scans';
import * as componentsApiModule from '@/services/api/components';
import * as vulnerabilitiesApiModule from '@/services/api/vulnerabilities';
import { mockComponent, mockVulnerability, mockConflictedMatch } from './fixtures';

describe('Detail Views (Etapa 10)', () => {
  const renderWithProviders = (
    initialRoute: string,
    element: React.ReactNode,
    path = initialRoute,
  ) => {
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    return render(
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <MemoryRouter initialEntries={[initialRoute]}>
            <Routes>
              <Route path={path} element={element} />
            </Routes>
          </MemoryRouter>
        </ToastProvider>
      </QueryClientProvider>,
    );
  };

  it('renders ProjectDetailPage with project information and scan launcher', async () => {
    vi.spyOn(projectsApiModule.projectsApi, 'get').mockResolvedValue({
      id: 'proj-123',
      name: 'E-Commerce Backend',
      path: '/repos/backend',
      created_at: '2026-10-01T00:00:00Z',
      updated_at: '2026-10-02T00:00:00Z',
    });
    vi.spyOn(scansApiModule.scansApi, 'list').mockResolvedValue({
      items: [
        {
          id: 'scan-abc-123',
          project_id: 'proj-123',
          status: 'completed',
          components_found: 12,
          vulnerabilities_found: 3,
          kev_matches: 1,
          duration_seconds: 4.5,
          started_at: '2026-10-02T10:00:00Z',
          completed_at: '2026-10-02T10:00:04Z',
          error: null,
        },
      ],
      page: 1,
      page_size: 20,
      total: 1,
    });
    vi.spyOn(componentsApiModule.componentsApi, 'list').mockResolvedValue({
      items: [mockComponent],
      page: 1,
      page_size: 100,
      total: 1,
    });

    renderWithProviders('/projects/proj-123', <ProjectDetailPage />, '/projects/:projectId');

    expect(await screen.findByText('E-Commerce Backend')).toBeInTheDocument();
    expect(screen.getByText('/repos/backend')).toBeInTheDocument();
    expect(screen.getByText('Run Security Scan')).toBeInTheDocument();
    expect(screen.getByText('Detected Project Dependencies')).toBeInTheDocument();
    expect(screen.getByText('urllib3')).toBeInTheDocument();
  });

  it('renders ScanDetailPage with scan results and matched findings', async () => {
    vi.spyOn(scansApiModule.scansApi, 'get').mockResolvedValue({
      id: 'scan-abc-123',
      project_id: 'proj-123',
      status: 'completed',
      components_found: 10,
      vulnerabilities_found: 1,
      kev_matches: 0,
      duration_seconds: 3.2,
      started_at: '2026-10-02T10:00:00Z',
      completed_at: '2026-10-02T10:00:03Z',
      error: null,
      matches: [mockConflictedMatch],
    });

    renderWithProviders('/scans/scan-abc-123', <ScanDetailPage />, '/scans/:scanId');

    expect(await screen.findByText(/Scan Execution: scan-abc/)).toBeInTheDocument();
    expect(screen.getByText('Correlated Vulnerability Matches')).toBeInTheDocument();
    expect(screen.getByText('REQUIRES_REVIEW')).toBeInTheDocument();
  });

  it('renders VulnerabilityDetailPage with advisory metadata and CISA KEV banner', async () => {
    vi.spyOn(vulnerabilitiesApiModule.vulnerabilitiesApi, 'get').mockResolvedValue(
      mockVulnerability,
    );

    renderWithProviders(
      '/vulnerabilities/vuln-789',
      <VulnerabilityDetailPage />,
      '/vulnerabilities/:vulnerabilityId',
    );

    const cveElements = await screen.findAllByText('CVE-2024-37891');
    expect(cveElements.length).toBeGreaterThan(0);
    expect(screen.getByText('CISA Known Exploited Vulnerability Advisory')).toBeInTheDocument();
    expect(screen.getByText('CWE-200')).toBeInTheDocument();
    expect(screen.getByText(/Proxy-Authorization Header Leak/)).toBeInTheDocument();
  });
});

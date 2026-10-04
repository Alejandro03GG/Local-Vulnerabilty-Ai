import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ToastProvider } from '@/components/ui/Toast';
import { LanguageProvider } from '@/i18n';
import { DashboardPage } from '@/pages/DashboardPage';
import { ProjectsPage } from '@/pages/ProjectsPage';
import { ScansPage } from '@/pages/ScansPage';
import { ComponentsPage } from '@/pages/ComponentsPage';
import { VulnerabilitiesPage } from '@/pages/VulnerabilitiesPage';
import { MatchesPage } from '@/pages/MatchesPage';
import { SourcesPage } from '@/pages/SourcesPage';
import { SettingsPage } from '@/pages/SettingsPage';
import { ContainerImagesPage } from '@/pages/ContainerImagesPage';
import * as healthApiModule from '@/services/api/health';
import * as projectsApiModule from '@/services/api/projects';
import * as scansApiModule from '@/services/api/scans';
import * as componentsApiModule from '@/services/api/components';
import * as vulnerabilitiesApiModule from '@/services/api/vulnerabilities';
import * as matchesApiModule from '@/services/api/matches';
import * as sourcesApiModule from '@/services/api/sources';
import * as imagesApiModule from '@/services/api/images';

describe('Application Routing and Core Pages (Etapa 10 §10)', () => {
  beforeEach(() => {
    vi.spyOn(healthApiModule.healthApi, 'check').mockResolvedValue({
      status: 'ok',
      database: 'connected',
      version: '1.0.0',
    });
    vi.spyOn(projectsApiModule.projectsApi, 'list').mockResolvedValue({
      items: [],
      page: 1,
      page_size: 20,
      total: 0,
    });
    vi.spyOn(scansApiModule.scansApi, 'list').mockResolvedValue({
      items: [],
      page: 1,
      page_size: 20,
      total: 0,
    });
    vi.spyOn(componentsApiModule.componentsApi, 'list').mockResolvedValue({
      items: [],
      page: 1,
      page_size: 20,
      total: 0,
    });
    vi.spyOn(vulnerabilitiesApiModule.vulnerabilitiesApi, 'list').mockResolvedValue({
      items: [],
      page: 1,
      page_size: 20,
      total: 0,
    });
    vi.spyOn(matchesApiModule.matchesApi, 'list').mockResolvedValue({
      items: [],
      page: 1,
      page_size: 20,
      total: 0,
    });
    vi.spyOn(sourcesApiModule.sourcesApi, 'list').mockResolvedValue([
      {
        id: 'osv',
        name: 'OSV',
        source_type: 'ecosystem',
        is_available: true,
        last_sync: '2026-10-01T00:00:00Z',
        record_count: 5000,
      },
    ]);
    vi.spyOn(imagesApiModule.imagesApi, 'list').mockResolvedValue({
      items: [],
      page: 1,
      page_size: 50,
      total: 0,
    });
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

  it('renders DashboardPage on "/"', async () => {
    renderWithProviders('/', <DashboardPage />);
    expect(await screen.findByText('Security Operations Dashboard')).toBeInTheDocument();
  });

  it('renders ProjectsPage on "/projects"', async () => {
    renderWithProviders('/projects', <ProjectsPage />);
    expect(await screen.findByText('Configured Projects')).toBeInTheDocument();
  });

  it('renders ScansPage on "/scans"', async () => {
    renderWithProviders('/scans', <ScansPage />);
    expect(await screen.findByText('Vulnerability Scans')).toBeInTheDocument();
  });

  it('renders ContainerImagesPage on "/images"', async () => {
    renderWithProviders('/images', <ContainerImagesPage />);
    expect(await screen.findByText('Container Images & Dockerfiles')).toBeInTheDocument();
  });

  it('renders ComponentsPage on "/components"', async () => {
    renderWithProviders('/components', <ComponentsPage />);
    expect(await screen.findByText('Software Components Inventory')).toBeInTheDocument();
  });

  it('renders VulnerabilitiesPage on "/vulnerabilities"', async () => {
    renderWithProviders('/vulnerabilities', <VulnerabilitiesPage />);
    expect(await screen.findByText('Vulnerability Intelligence Catalog')).toBeInTheDocument();
  });

  it('renders MatchesPage on "/matches"', async () => {
    renderWithProviders('/matches', <MatchesPage />);
    expect(await screen.findByText('Vulnerability Matches & Correlations')).toBeInTheDocument();
  });

  it('renders SourcesPage on "/sources"', async () => {
    renderWithProviders('/sources', <SourcesPage />);
    expect(await screen.findByText('Vulnerability Intelligence Sources')).toBeInTheDocument();
  });

  it('renders SettingsPage on "/settings"', async () => {
    renderWithProviders('/settings', <SettingsPage />);
    expect(await screen.findByText('Settings & System Diagnostics')).toBeInTheDocument();
  });
});

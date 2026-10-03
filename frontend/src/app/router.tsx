import { createBrowserRouter } from 'react-router-dom';
import { AppShell } from '@/components/layout/AppShell';
import { DashboardPage } from '@/pages/DashboardPage';
import { ProjectsPage } from '@/pages/ProjectsPage';
import { ProjectDetailPage } from '@/pages/ProjectDetailPage';
import { ScansPage } from '@/pages/ScansPage';
import { ScanDetailPage } from '@/pages/ScanDetailPage';
import { ComponentsPage } from '@/pages/ComponentsPage';
import { VulnerabilitiesPage } from '@/pages/VulnerabilitiesPage';
import { VulnerabilityDetailPage } from '@/pages/VulnerabilityDetailPage';
import { MatchesPage } from '@/pages/MatchesPage';
import { MatchDetailPage } from '@/pages/MatchDetailPage';
import { PoliciesPage } from '@/pages/PoliciesPage';
import { SuppressionsPage } from '@/pages/SuppressionsPage';
import { SourcesPage } from '@/pages/SourcesPage';
import { SettingsPage } from '@/pages/SettingsPage';
import { ContainerImagesPage } from '@/pages/ContainerImagesPage';
import { ImageDetailPage } from '@/pages/ImageDetailPage';

export const router = createBrowserRouter([
  {
    path: '/',
    element: <AppShell />,
    children: [
      { index: true, element: <DashboardPage /> },
      { path: 'projects', element: <ProjectsPage /> },
      { path: 'projects/:projectId', element: <ProjectDetailPage /> },
      { path: 'scans', element: <ScansPage /> },
      { path: 'scans/:scanId', element: <ScanDetailPage /> },
      { path: 'images', element: <ContainerImagesPage /> },
      { path: 'images/:imageId', element: <ImageDetailPage /> },
      { path: 'components', element: <ComponentsPage /> },
      { path: 'vulnerabilities', element: <VulnerabilitiesPage /> },
      { path: 'vulnerabilities/:vulnerabilityId', element: <VulnerabilityDetailPage /> },
      { path: 'matches', element: <MatchesPage /> },
      { path: 'matches/:matchId', element: <MatchDetailPage /> },
      { path: 'policies', element: <PoliciesPage /> },
      { path: 'suppressions', element: <SuppressionsPage /> },
      { path: 'sources', element: <SourcesPage /> },
      { path: 'settings', element: <SettingsPage /> },
    ],
  },
]);

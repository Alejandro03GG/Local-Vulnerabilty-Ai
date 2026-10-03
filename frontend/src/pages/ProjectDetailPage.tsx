import React from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Play, Calendar, HardDrive, CheckCircle2 } from 'lucide-react';
import { PageHeader } from '@/components/layout/PageHeader';
import { DataTable, Column } from '@/components/ui/DataTable';
import { ScanStatusBadge } from '@/components/badges/ScanStatusBadge';
import { ErrorState } from '@/components/ui/ErrorState';
import { LoadingState } from '@/components/ui/LoadingState';
import { Metric } from '@/components/ui/Metric';
import { useToast } from '@/hooks/useToast';
import { projectsApi } from '@/services/api/projects';
import { scansApi } from '@/services/api/scans';
import { componentsApi } from '@/services/api/components';
import { formatDate, formatDuration } from '@/lib/utils';
import type { Scan, DetectedComponent } from '@/types';

export const ProjectDetailPage: React.FC = () => {
  const { projectId } = useParams<{ projectId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { showToast } = useToast();

  const {
    data: project,
    isLoading: isProjectLoading,
    isError: isProjectError,
    error: projectError,
  } = useQuery({
    queryKey: ['project', projectId],
    queryFn: () => projectsApi.get(projectId!),
    enabled: Boolean(projectId),
  });

  const { data: scansData, isLoading: isScansLoading } = useQuery({
    queryKey: ['project-scans', projectId],
    queryFn: () => scansApi.list(projectId, 1, 20),
    enabled: Boolean(projectId),
  });

  const { data: componentsData, isLoading: isComponentsLoading } = useQuery({
    queryKey: ['project-components', projectId],
    queryFn: () => componentsApi.list(projectId, 1, 100),
    enabled: Boolean(projectId),
  });

  const scanMutation = useMutation({
    mutationFn: () => scansApi.runProjectScan(projectId!),
    onSuccess: (newScan) => {
      queryClient.invalidateQueries({ queryKey: ['project-scans', projectId] });
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      showToast(
        'success',
        'Scan initiated',
        `Execution started (ID: ${newScan.id.substring(0, 8)})`,
      );
      navigate(`/scans/${newScan.id}`);
    },
    onError: (err: { message: string }) => {
      showToast('error', 'Scan failed', err.message);
    },
  });

  if (isProjectLoading) {
    return <LoadingState message="Loading project configuration..." />;
  }

  if (isProjectError || !project) {
    return (
      <ErrorState
        title="Project Not Found"
        description="The requested project identifier could not be retrieved from the database."
        requestId={(projectError as { requestId?: string })?.requestId}
        onRetry={() => navigate('/projects')}
      />
    );
  }

  const scans = scansData?.items ?? [];
  const components = componentsData?.items ?? [];

  const latestScan = scans.length > 0 ? scans[0] : null;

  const scanColumns: Column<Scan>[] = [
    {
      key: 'id',
      header: 'Scan ID',
      render: (s) => (
        <span className="font-mono text-xs text-blue-400 font-semibold">
          {s.id.substring(0, 8)}
        </span>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      render: (s) => <ScanStatusBadge status={s.status} />,
    },
    {
      key: 'started_at',
      header: 'Executed',
      render: (s) => <span className="font-mono text-xs">{formatDate(s.started_at)}</span>,
    },
    {
      key: 'duration_seconds',
      header: 'Duration',
      render: (s) => (
        <span className="font-mono text-xs">{formatDuration(s.duration_seconds)}</span>
      ),
    },
    {
      key: 'components_found',
      header: 'Components',
      render: (s) => <span className="font-mono text-xs">{s.components_found}</span>,
    },
    {
      key: 'vulnerabilities_found',
      header: 'Matches',
      render: (s) => (
        <span className="font-mono text-xs font-semibold text-soc-primary">
          {s.vulnerabilities_found}
        </span>
      ),
    },
  ];

  const componentColumns: Column<DetectedComponent>[] = [
    {
      key: 'name',
      header: 'Package',
      render: (c) => <span className="font-mono font-semibold text-soc-primary">{c.name}</span>,
    },
    {
      key: 'version',
      header: 'Installed Version',
      render: (c) => (
        <span className="font-mono text-xs text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded border border-blue-500/20">
          {c.version || '—'}
        </span>
      ),
    },
    {
      key: 'ecosystem',
      header: 'Ecosystem',
      render: (c) => (
        <span className="font-mono text-xs uppercase text-soc-secondary">{c.ecosystem}</span>
      ),
    },
    {
      key: 'source_file',
      header: 'Manifest / Lockfile',
      render: (c) => (
        <span
          className="font-mono text-xs text-soc-muted truncate max-w-xs block"
          title={c.source_file}
        >
          {c.source_file}
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-6" data-testid="project-detail-page">
      <PageHeader
        title={project.name}
        subtitle={project.path}
        backTo="/projects"
        actions={
          <button
            onClick={() => scanMutation.mutate()}
            disabled={scanMutation.isPending}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-blue-600 rounded-md hover:bg-blue-500 transition-colors shadow-sm disabled:opacity-50"
          >
            <Play className="w-3.5 h-3.5" />
            <span>{scanMutation.isPending ? 'Starting Scan...' : 'Run Security Scan'}</span>
          </button>
        }
      />

      {/* Project Meta Card */}
      <div className="p-4 rounded-lg border border-soc-border bg-soc-surface grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs font-mono">
        <div className="flex items-center gap-2 text-soc-secondary">
          <HardDrive className="w-4 h-4 text-soc-muted shrink-0" />
          <span className="truncate">Path: {project.path}</span>
        </div>
        <div className="flex items-center gap-2 text-soc-secondary">
          <Calendar className="w-4 h-4 text-soc-muted shrink-0" />
          <span>Registered: {formatDate(project.created_at)}</span>
        </div>
        <div className="flex items-center gap-2 text-soc-secondary">
          <CheckCircle2 className="w-4 h-4 text-soc-muted shrink-0" />
          <span>Last Updated: {formatDate(project.updated_at)}</span>
        </div>
      </div>

      {/* Metrics */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Metric label="Total Scans" value={scans.length} subtext="Executed for project" />
        <Metric label="Components" value={components.length} subtext="Tracked dependencies" />
        <Metric
          label="Latest Matches"
          value={latestScan?.vulnerabilities_found ?? 0}
          subtext="Vulnerabilities correlated"
        />
        <Metric
          label="KEV Exploits"
          value={latestScan?.kev_matches ?? 0}
          subtext="CISA cataloged"
          variant={latestScan && latestScan.kev_matches > 0 ? 'critical' : 'default'}
        />
      </div>

      {/* Recent Scans Section */}
      <div className="space-y-3">
        <h2 className="text-sm font-semibold text-soc-primary">Execution History</h2>
        <DataTable
          columns={scanColumns}
          data={scans}
          keyExtractor={(s) => s.id}
          isLoading={isScansLoading}
          emptyTitle="No scans executed"
          emptyDescription="Click 'Run Security Scan' above to scan this project's dependencies."
          onRowClick={(s) => navigate(`/scans/${s.id}`)}
        />
      </div>

      {/* Detected Components Section */}
      <div className="space-y-3">
        <h2 className="text-sm font-semibold text-soc-primary">Detected Project Dependencies</h2>
        <DataTable
          columns={componentColumns}
          data={components}
          keyExtractor={(c) => c.id}
          isLoading={isComponentsLoading}
          emptyTitle="No components recorded"
          emptyDescription="Components will be extracted automatically during scan execution."
        />
      </div>
    </div>
  );
};

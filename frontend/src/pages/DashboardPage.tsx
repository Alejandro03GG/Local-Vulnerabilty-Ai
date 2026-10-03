import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import {
  FolderGit2,
  Scan as ScanIcon,
  Package,
  ShieldAlert,
  AlertTriangle,
  Play,
} from 'lucide-react';
import { PageHeader } from '@/components/layout/PageHeader';
import { Metric } from '@/components/ui/Metric';
import { DataTable, Column } from '@/components/ui/DataTable';
import { RiskBadge } from '@/components/badges/RiskBadge';
import { ScanStatusBadge } from '@/components/badges/ScanStatusBadge';
import { SourceStatusBadge } from '@/components/badges/SourceStatusBadge';
import { ErrorState } from '@/components/ui/ErrorState';
import { projectsApi } from '@/services/api/projects';
import { scansApi } from '@/services/api/scans';
import { componentsApi } from '@/services/api/components';
import { vulnerabilitiesApi } from '@/services/api/vulnerabilities';
import { matchesApi } from '@/services/api/matches';
import { sourcesApi } from '@/services/api/sources';
import { formatDate, formatDuration } from '@/lib/utils';
import type { Scan } from '@/types';

export const DashboardPage: React.FC = () => {
  const navigate = useNavigate();

  const {
    data: projectsData,
    isError: isProjectsError,
    error: projectsError,
  } = useQuery({
    queryKey: ['projects', 1, 100],
    queryFn: () => projectsApi.list(1, 100),
  });

  const { data: scansData, isLoading: isScansLoading } = useQuery({
    queryKey: ['scans', 'recent'],
    queryFn: () => scansApi.list(undefined, 1, 5),
  });

  const { data: componentsData } = useQuery({
    queryKey: ['components', 'summary'],
    queryFn: () => componentsApi.list(undefined, 1, 1),
  });

  const { data: vulnerabilitiesData } = useQuery({
    queryKey: ['vulnerabilities', 'summary'],
    queryFn: () => vulnerabilitiesApi.list(undefined, 1, 1),
  });

  const { data: matchesData } = useQuery({
    queryKey: ['matches', 'all'],
    queryFn: () => matchesApi.list(undefined, undefined, 1, 100),
  });

  const { data: sourcesData } = useQuery({
    queryKey: ['sources'],
    queryFn: sourcesApi.list,
  });

  if (isProjectsError) {
    return (
      <ErrorState
        title="Failed to Load Dashboard Data"
        description="Could not connect to the Local Vulnerability AI backend service."
        requestId={(projectsError as { requestId?: string })?.requestId}
      />
    );
  }

  // Calculate real metrics from fetched backend records (no fake numbers!)
  const totalProjects = projectsData?.total ?? 0;
  const activeScans =
    scansData?.items.filter((s) => s.status === 'running' || s.status === 'pending').length ?? 0;
  const totalComponents = componentsData?.total ?? 0;
  const totalVulnerabilities = vulnerabilitiesData?.total ?? 0;

  const matches = matchesData?.items ?? [];
  const requiresReviewCount = matches.filter(
    (m) => m.applicability === 'REQUIRES_REVIEW' || m.risk_assessment?.requires_human_review,
  ).length;

  const riskDistribution = {
    critical: matches.filter((m) => m.risk_assessment?.risk_level === 'CRITICAL').length,
    high: matches.filter((m) => m.risk_assessment?.risk_level === 'HIGH').length,
    medium: matches.filter((m) => m.risk_assessment?.risk_level === 'MEDIUM').length,
    low: matches.filter((m) => m.risk_assessment?.risk_level === 'LOW').length,
  };

  const recentScans = scansData?.items ?? [];

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
      header: 'Started',
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
    {
      key: 'kev_matches',
      header: 'KEV Exploited',
      render: (s) =>
        s.kev_matches > 0 ? (
          <span className="font-mono text-xs text-red-400 font-bold px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/30">
            {s.kev_matches} KEV
          </span>
        ) : (
          <span className="font-mono text-xs text-soc-muted">0</span>
        ),
    },
  ];

  return (
    <div className="space-y-6" data-testid="dashboard-page">
      <PageHeader
        title="Security Operations Dashboard"
        subtitle="Real-time dependency posture, vulnerability correlation, and threat intelligence telemetry"
        actions={
          <button
            onClick={() => navigate('/projects')}
            className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-semibold text-white bg-blue-600 rounded-md hover:bg-blue-500 transition-colors shadow-sm"
          >
            <Play className="w-3.5 h-3.5" />
            <span>Launch Project Scan</span>
          </button>
        }
      />

      {/* Top Telemetry Metrics */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3.5">
        <Metric
          label="Tracked Projects"
          value={totalProjects}
          subtext="Configured targets"
          icon={FolderGit2}
        />
        <Metric
          label="Active Scans"
          value={activeScans}
          subtext="Executing in engine"
          icon={ScanIcon}
          variant={activeScans > 0 ? 'info' : 'default'}
        />
        <Metric
          label="Components Sourced"
          value={totalComponents}
          subtext="Dependencies detected"
          icon={Package}
        />
        <Metric
          label="Vulnerabilities DB"
          value={totalVulnerabilities}
          subtext="Authoritative advisories"
          icon={ShieldAlert}
        />
        <Metric
          label="Requires Human Review"
          value={requiresReviewCount}
          subtext="Uncertainty / conflicts"
          icon={AlertTriangle}
          variant={requiresReviewCount > 0 ? 'warning' : 'default'}
        />
      </div>

      {/* Risk Distribution and Source Health split */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Overview */}
        <div className="lg:col-span-2 p-5 rounded-lg border border-soc-border bg-soc-surface">
          <div className="flex items-center justify-between pb-3 mb-4 border-b border-soc-border">
            <h2 className="text-sm font-semibold text-soc-primary">Risk Severity Posture</h2>
            <span className="text-[11px] font-mono text-soc-muted uppercase">
              Deterministic Engine Output
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3.5 rounded bg-soc-elevated border border-soc-border">
              <RiskBadge level="CRITICAL" />
              <div className="text-2xl font-bold font-mono text-red-400 mt-2">
                {riskDistribution.critical}
              </div>
              <span className="text-[11px] text-soc-muted block mt-0.5">Urgent triage needed</span>
            </div>

            <div className="p-3.5 rounded bg-soc-elevated border border-soc-border">
              <RiskBadge level="HIGH" />
              <div className="text-2xl font-bold font-mono text-orange-400 mt-2">
                {riskDistribution.high}
              </div>
              <span className="text-[11px] text-soc-muted block mt-0.5">
                High severity exploit risk
              </span>
            </div>

            <div className="p-3.5 rounded bg-soc-elevated border border-soc-border">
              <RiskBadge level="MEDIUM" />
              <div className="text-2xl font-bold font-mono text-amber-400 mt-2">
                {riskDistribution.medium}
              </div>
              <span className="text-[11px] text-soc-muted block mt-0.5">Moderate impact</span>
            </div>

            <div className="p-3.5 rounded bg-soc-elevated border border-soc-border">
              <RiskBadge level="LOW" />
              <div className="text-2xl font-bold font-mono text-blue-400 mt-2">
                {riskDistribution.low}
              </div>
              <span className="text-[11px] text-soc-muted block mt-0.5">Low technical risk</span>
            </div>
          </div>
        </div>

        {/* Intelligence Sources Status */}
        <div className="p-5 rounded-lg border border-soc-border bg-soc-surface">
          <div className="flex items-center justify-between pb-3 mb-4 border-b border-soc-border">
            <h2 className="text-sm font-semibold text-soc-primary">Intelligence Sources</h2>
            <button
              onClick={() => navigate('/sources')}
              className="text-xs text-blue-400 hover:text-blue-300 font-mono"
            >
              Manage Sources →
            </button>
          </div>

          <div className="space-y-3">
            {sourcesData && sourcesData.length > 0 ? (
              sourcesData.map((src) => (
                <div
                  key={src.id}
                  className="p-3 rounded bg-soc-elevated border border-soc-border flex items-center justify-between"
                >
                  <div>
                    <span className="text-xs font-semibold text-soc-primary block">{src.name}</span>
                    <span className="text-[10px] font-mono text-soc-muted block">
                      {src.record_count.toLocaleString()} records • {formatDate(src.last_sync)}
                    </span>
                  </div>
                  <SourceStatusBadge isAvailable={src.is_available} />
                </div>
              ))
            ) : (
              <div className="text-xs text-soc-muted font-mono p-4 text-center">
                Querying configured intelligence sources...
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-soc-primary">Recent Vulnerability Scans</h2>
          <button
            onClick={() => navigate('/scans')}
            className="text-xs text-blue-400 hover:text-blue-300 font-mono"
          >
            View all scans →
          </button>
        </div>

        <DataTable
          columns={scanColumns}
          data={recentScans}
          keyExtractor={(s) => s.id}
          isLoading={isScansLoading}
          emptyTitle="No scans executed yet"
          emptyDescription="Configure a project and trigger a security scan to evaluate components against vulnerability intelligence."
          onRowClick={(s) => navigate(`/scans/${s.id}`)}
        />
      </div>
    </div>
  );
};

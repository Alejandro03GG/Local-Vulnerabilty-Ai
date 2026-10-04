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
import { useI18n } from '@/i18n';
import { DASHBOARD_MOCK_ENABLED, dashboardMock } from '@/mocks/dashboardMock';
import type { Scan } from '@/types';

export const DashboardPage: React.FC = () => {
  const navigate = useNavigate();
  const { t, dateLocale } = useI18n();

  const useMock = DASHBOARD_MOCK_ENABLED;

  const {
    data: projectsData,
    isError: isProjectsError,
    error: projectsError,
  } = useQuery({
    queryKey: ['projects', 1, 100],
    queryFn: () => projectsApi.list(1, 100),
    enabled: !useMock,
  });

  const { data: scansData, isLoading: isScansLoading } = useQuery({
    queryKey: ['scans', 'recent'],
    queryFn: () => scansApi.list(undefined, 1, 5),
    enabled: !useMock,
  });

  const { data: componentsData } = useQuery({
    queryKey: ['components', 'summary'],
    queryFn: () => componentsApi.list(undefined, 1, 1),
    enabled: !useMock,
  });

  const { data: vulnerabilitiesData } = useQuery({
    queryKey: ['vulnerabilities', 'summary'],
    queryFn: () => vulnerabilitiesApi.list(undefined, 1, 1),
    enabled: !useMock,
  });

  const { data: matchesData } = useQuery({
    queryKey: ['matches', 'all'],
    queryFn: () => matchesApi.list(undefined, undefined, 1, 100),
    enabled: !useMock,
  });

  const { data: sourcesData } = useQuery({
    queryKey: ['sources'],
    queryFn: sourcesApi.list,
    enabled: !useMock,
  });

  if (!useMock && isProjectsError) {
    return (
      <ErrorState
        title={t('dashboard.errorTitle')}
        description={t('dashboard.errorDescription')}
        requestId={(projectsError as { requestId?: string })?.requestId}
      />
    );
  }

  const projects = useMock ? dashboardMock.projects : projectsData;
  const scans = useMock ? dashboardMock.scans : scansData;
  const componentsTotal = useMock ? dashboardMock.componentsTotal : (componentsData?.total ?? 0);
  const vulnerabilitiesTotal = useMock
    ? dashboardMock.vulnerabilitiesTotal
    : (vulnerabilitiesData?.total ?? 0);
  const matchItems = useMock ? dashboardMock.matches.items : (matchesData?.items ?? []);
  const sources = useMock ? dashboardMock.sources : sourcesData;

  const totalProjects = projects?.total ?? 0;
  const activeScans =
    scans?.items.filter((s) => s.status === 'running' || s.status === 'pending').length ?? 0;
  const totalComponents = componentsTotal;
  const totalVulnerabilities = vulnerabilitiesTotal;

  const matches = matchItems;
  const requiresReviewCount = matches.filter(
    (m) => m.applicability === 'REQUIRES_REVIEW' || m.risk_assessment?.requires_human_review,
  ).length;

  const riskLevel = (m: (typeof matches)[number]) =>
    (m.risk_assessment?.risk_level || '').toUpperCase();
  const isTechnicallyApplicable = (m: (typeof matches)[number]) =>
    m.applicability !== 'likely_not_affected' && m.applicability !== 'LIKELY_NOT_AFFECTED';

  const riskDistribution = {
    critical: matches.filter((m) => riskLevel(m) === 'CRITICAL' && isTechnicallyApplicable(m)).length,
    high: matches.filter((m) => riskLevel(m) === 'HIGH' && isTechnicallyApplicable(m)).length,
    medium: matches.filter((m) => riskLevel(m) === 'MEDIUM' && isTechnicallyApplicable(m)).length,
    low: matches.filter((m) => riskLevel(m) === 'LOW' && isTechnicallyApplicable(m)).length,
  };

  const recentScans = scans?.items ?? [];

  const scanColumns: Column<Scan>[] = [
    {
      key: 'id',
      header: t('dashboard.cols.scanId'),
      render: (s) => (
        <span className="font-mono text-xs text-blue-400 font-semibold">
          {s.id.substring(0, 8)}
        </span>
      ),
    },
    {
      key: 'status',
      header: t('dashboard.cols.status'),
      render: (s) => <ScanStatusBadge status={s.status} />,
    },
    {
      key: 'started_at',
      header: t('dashboard.cols.started'),
      render: (s) => (
        <span className="font-mono text-xs">{formatDate(s.started_at, dateLocale)}</span>
      ),
    },
    {
      key: 'duration_seconds',
      header: t('dashboard.cols.duration'),
      render: (s) => (
        <span className="font-mono text-xs">{formatDuration(s.duration_seconds)}</span>
      ),
    },
    {
      key: 'components_found',
      header: t('dashboard.cols.components'),
      render: (s) => <span className="font-mono text-xs">{s.components_found}</span>,
    },
    {
      key: 'vulnerabilities_found',
      header: t('dashboard.cols.matches'),
      render: (s) => (
        <span className="font-mono text-xs font-semibold text-soc-primary">
          {s.vulnerabilities_found}
        </span>
      ),
    },
    {
      key: 'kev_matches',
      header: t('dashboard.cols.kevExploited'),
      render: (s) =>
        s.kev_matches > 0 ? (
          <span className="font-mono text-xs text-red-400 font-bold px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/30">
            {t('dashboard.kevCount', { count: s.kev_matches })}
          </span>
        ) : (
          <span className="font-mono text-xs text-soc-muted">0</span>
        ),
    },
  ];

  return (
    <div className="space-y-6" data-testid="dashboard-page">
      <PageHeader
        title={t('dashboard.title')}
        subtitle={t('dashboard.subtitle')}
        actions={
          <button
            onClick={() => navigate('/projects')}
            className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-semibold text-white bg-blue-600 rounded-md hover:bg-blue-500 transition-colors shadow-sm"
          >
            <Play className="w-3.5 h-3.5" />
            <span>{t('dashboard.launchScan')}</span>
          </button>
        }
      />

      {/* Top Telemetry Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-3.5">
        <Metric
          label={t('dashboard.metrics.projects')}
          value={totalProjects}
          subtext={t('dashboard.metrics.projectsHint')}
          icon={FolderGit2}
        />
        <Metric
          label={t('dashboard.metrics.activeScans')}
          value={activeScans}
          subtext={t('dashboard.metrics.activeScansHint')}
          icon={ScanIcon}
          variant={activeScans > 0 ? 'info' : 'default'}
        />
        <Metric
          label={t('dashboard.metrics.components')}
          value={totalComponents}
          subtext={t('dashboard.metrics.componentsHint')}
          icon={Package}
        />
        <Metric
          label={t('dashboard.metrics.vulnerabilities')}
          value={totalVulnerabilities}
          subtext={t('dashboard.metrics.vulnerabilitiesHint')}
          icon={ShieldAlert}
        />
        <Metric
          label={t('dashboard.metrics.review')}
          value={requiresReviewCount}
          subtext={t('dashboard.metrics.reviewHint')}
          icon={AlertTriangle}
          variant={requiresReviewCount > 0 ? 'warning' : 'default'}
        />
      </div>

      {/* Risk Distribution and Source Health split */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Overview */}
        <div className="lg:col-span-2 p-5 rounded-lg border border-soc-border bg-soc-surface">
          <div className="flex items-center justify-between pb-3 mb-4 border-b border-soc-border">
            <h2 className="text-sm font-semibold text-soc-primary">{t('dashboard.risk.title')}</h2>
            <span className="text-[11px] font-mono text-soc-muted uppercase">
              {t('dashboard.risk.engineOutput')}
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3">
            <div className="p-3.5 rounded bg-soc-elevated border border-soc-border">
              <RiskBadge level="CRITICAL" />
              <div className="text-2xl font-bold font-mono text-red-400 mt-2">
                {riskDistribution.critical}
              </div>
              <span className="text-[11px] text-soc-muted block mt-0.5">
                {t('dashboard.risk.criticalHint')}
              </span>
            </div>

            <div className="p-3.5 rounded bg-soc-elevated border border-soc-border">
              <RiskBadge level="HIGH" />
              <div className="text-2xl font-bold font-mono text-orange-400 mt-2">
                {riskDistribution.high}
              </div>
              <span className="text-[11px] text-soc-muted block mt-0.5">
                {t('dashboard.risk.highHint')}
              </span>
            </div>

            <div className="p-3.5 rounded bg-soc-elevated border border-soc-border">
              <RiskBadge level="MEDIUM" />
              <div className="text-2xl font-bold font-mono text-amber-400 mt-2">
                {riskDistribution.medium}
              </div>
              <span className="text-[11px] text-soc-muted block mt-0.5">
                {t('dashboard.risk.mediumHint')}
              </span>
            </div>

            <div className="p-3.5 rounded bg-soc-elevated border border-soc-border">
              <RiskBadge level="LOW" />
              <div className="text-2xl font-bold font-mono text-blue-400 mt-2">
                {riskDistribution.low}
              </div>
              <span className="text-[11px] text-soc-muted block mt-0.5">
                {t('dashboard.risk.lowHint')}
              </span>
            </div>
          </div>
        </div>

        {/* Intelligence Sources Status */}
        <div className="p-5 rounded-lg border border-soc-border bg-soc-surface">
          <div className="flex items-center justify-between pb-3 mb-4 border-b border-soc-border">
            <h2 className="text-sm font-semibold text-soc-primary">
              {t('dashboard.sources.title')}
            </h2>
            <button
              onClick={() => navigate('/sources')}
              className="text-xs text-blue-400 hover:text-blue-300 font-mono"
            >
              {t('dashboard.sources.manage')}
            </button>
          </div>

          <div className="space-y-3">
            {sources && sources.length > 0 ? (
              sources.map((src) => (
                <div
                  key={src.id}
                  className="p-3 rounded bg-soc-elevated border border-soc-border flex items-center justify-between gap-3 min-w-0"
                >
                  <div className="min-w-0 flex-1">
                    <span className="text-xs font-semibold text-soc-primary block truncate">
                      {src.name}
                    </span>
                    <span className="text-[10px] font-mono text-soc-muted block truncate">
                      {t('dashboard.sources.records', {
                        count: src.record_count.toLocaleString(dateLocale),
                        date: formatDate(src.last_sync, dateLocale),
                      })}
                    </span>
                  </div>
                  <SourceStatusBadge status={src.status} isAvailable={src.is_available} />
                </div>
              ))
            ) : (
              <div className="text-xs text-soc-muted font-mono p-4 text-center">
                {t('dashboard.sources.querying')}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-soc-primary">{t('dashboard.recent.title')}</h2>
          <button
            onClick={() => navigate('/scans')}
            className="text-xs text-blue-400 hover:text-blue-300 font-mono"
          >
            {t('dashboard.recent.viewAll')}
          </button>
        </div>

        <DataTable
          columns={scanColumns}
          data={recentScans}
          keyExtractor={(s) => s.id}
          isLoading={!useMock && isScansLoading}
          emptyTitle={t('dashboard.recent.emptyTitle')}
          emptyDescription={t('dashboard.recent.emptyDescription')}
          onRowClick={(s) => navigate(`/scans/${s.id}`)}
        />
      </div>
    </div>
  );
};

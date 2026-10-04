import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { PageHeader } from '@/components/layout/PageHeader';
import { DataTable, Column } from '@/components/ui/DataTable';
import { ScanStatusBadge } from '@/components/badges/ScanStatusBadge';
import { ErrorState } from '@/components/ui/ErrorState';
import { scansApi } from '@/services/api/scans';
import { formatDate, formatDuration } from '@/lib/utils';
import { useI18n } from '@/i18n';
import type { Scan } from '@/types';

export const ScansPage: React.FC = () => {
  const navigate = useNavigate();
  const { t, dateLocale } = useI18n();
  const [page] = useState(1);

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['scans', page],
    queryFn: () => scansApi.list(undefined, page, 50),
    // Polling only while there are pending or running scans (Section 48)
    refetchInterval: (query) => {
      const scans = query.state.data?.items ?? [];
      const hasActive = scans.some((s) => s.status === 'running' || s.status === 'pending');
      return hasActive ? 3000 : false;
    },
  });

  const columns: Column<Scan>[] = [
    {
      key: 'id',
      header: t('scans.cols.scanId'),
      sortable: true,
      render: (s) => (
        <span className="font-mono text-xs font-semibold text-blue-400">
          {s.id.substring(0, 8)}
        </span>
      ),
    },
    {
      key: 'status',
      header: t('scans.cols.status'),
      sortable: true,
      render: (s) => <ScanStatusBadge status={s.status} />,
    },
    {
      key: 'project_id',
      header: t('scans.cols.projectId'),
      render: (s) => (
        <span className="font-mono text-xs text-soc-secondary">{s.project_id.substring(0, 8)}</span>
      ),
    },
    {
      key: 'started_at',
      header: t('scans.cols.startedAt'),
      sortable: true,
      render: (s) => (
        <span className="font-mono text-xs">{formatDate(s.started_at, dateLocale)}</span>
      ),
    },
    {
      key: 'duration_seconds',
      header: t('scans.cols.duration'),
      sortable: true,
      render: (s) => (
        <span className="font-mono text-xs">{formatDuration(s.duration_seconds)}</span>
      ),
    },
    {
      key: 'components_found',
      header: t('scans.cols.components'),
      sortable: true,
      render: (s) => <span className="font-mono text-xs">{s.components_found}</span>,
    },
    {
      key: 'vulnerabilities_found',
      header: t('scans.cols.matchesFound'),
      sortable: true,
      render: (s) => (
        <span className="font-mono text-xs font-semibold text-soc-primary">
          {s.vulnerabilities_found}
        </span>
      ),
    },
    {
      key: 'kev_matches',
      header: t('scans.cols.kevExploited'),
      sortable: true,
      render: (s) =>
        s.kev_matches > 0 ? (
          <span className="font-mono text-xs text-red-400 font-bold px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/30">
            {t('scans.kevCount', { count: s.kev_matches })}
          </span>
        ) : (
          <span className="font-mono text-xs text-soc-muted">0</span>
        ),
    },
  ];

  if (isError) {
    return (
      <ErrorState
        title={t('scans.errorTitle')}
        description={t('scans.errorDescription')}
        requestId={(error as { requestId?: string })?.requestId}
        onRetry={() => refetch()}
      />
    );
  }

  return (
    <div className="space-y-6" data-testid="scans-page">
      <PageHeader title={t('scans.title')} subtitle={t('scans.subtitle')} />

      <DataTable
        columns={columns}
        data={data?.items ?? []}
        keyExtractor={(s) => s.id}
        isLoading={isLoading}
        emptyTitle={t('scans.emptyTitle')}
        emptyDescription={t('scans.emptyDescription')}
        onRowClick={(s) => navigate(`/scans/${s.id}`)}
      />
    </div>
  );
};

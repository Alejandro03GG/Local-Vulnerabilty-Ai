import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { PageHeader } from '@/components/layout/PageHeader';
import { DataTable, Column } from '@/components/ui/DataTable';
import { ScanStatusBadge } from '@/components/badges/ScanStatusBadge';
import { ErrorState } from '@/components/ui/ErrorState';
import { scansApi } from '@/services/api/scans';
import { formatDate, formatDuration } from '@/lib/utils';
import type { Scan } from '@/types';

export const ScansPage: React.FC = () => {
  const navigate = useNavigate();
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
      header: 'Scan ID',
      sortable: true,
      render: (s) => (
        <span className="font-mono text-xs font-semibold text-blue-400">
          {s.id.substring(0, 8)}
        </span>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      sortable: true,
      render: (s) => <ScanStatusBadge status={s.status} />,
    },
    {
      key: 'project_id',
      header: 'Project ID',
      render: (s) => (
        <span className="font-mono text-xs text-soc-secondary">{s.project_id.substring(0, 8)}</span>
      ),
    },
    {
      key: 'started_at',
      header: 'Started At',
      sortable: true,
      render: (s) => <span className="font-mono text-xs">{formatDate(s.started_at)}</span>,
    },
    {
      key: 'duration_seconds',
      header: 'Duration',
      sortable: true,
      render: (s) => (
        <span className="font-mono text-xs">{formatDuration(s.duration_seconds)}</span>
      ),
    },
    {
      key: 'components_found',
      header: 'Components',
      sortable: true,
      render: (s) => <span className="font-mono text-xs">{s.components_found}</span>,
    },
    {
      key: 'vulnerabilities_found',
      header: 'Matches Found',
      sortable: true,
      render: (s) => (
        <span className="font-mono text-xs font-semibold text-soc-primary">
          {s.vulnerabilities_found}
        </span>
      ),
    },
    {
      key: 'kev_matches',
      header: 'KEV Exploited',
      sortable: true,
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

  if (isError) {
    return (
      <ErrorState
        title="Failed to Load Scans"
        description="Could not query execution telemetry from the local engine."
        requestId={(error as { requestId?: string })?.requestId}
        onRetry={() => refetch()}
      />
    );
  }

  return (
    <div className="space-y-6" data-testid="scans-page">
      <PageHeader
        title="Vulnerability Scans"
        subtitle="Historical and in-progress scan executions against project dependencies"
      />

      <DataTable
        columns={columns}
        data={data?.items ?? []}
        keyExtractor={(s) => s.id}
        isLoading={isLoading}
        emptyTitle="No scans executed yet"
        emptyDescription="Start a scan from the Projects page to inspect dependencies for vulnerabilities."
        onRowClick={(s) => navigate(`/scans/${s.id}`)}
      />
    </div>
  );
};

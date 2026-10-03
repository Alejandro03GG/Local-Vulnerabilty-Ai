import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { Crosshair, Filter } from 'lucide-react';
import { PageHeader } from '@/components/layout/PageHeader';
import { DataTable, Column } from '@/components/ui/DataTable';
import { ApplicabilityBadge } from '@/components/badges/ApplicabilityBadge';
import { RiskBadge } from '@/components/badges/RiskBadge';
import { ReviewBadge } from '@/components/badges/ReviewBadge';
import { ErrorState } from '@/components/ui/ErrorState';
import { matchesApi } from '@/services/api/matches';
import { formatDate } from '@/lib/utils';
import type { Match, ApplicabilityType } from '@/types';

export const MatchesPage: React.FC = () => {
  const navigate = useNavigate();
  const [page] = useState(1);
  const [selectedApplicability, setSelectedApplicability] = useState<string>('');

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['matches', page, selectedApplicability],
    queryFn: () => matchesApi.list(undefined, selectedApplicability || undefined, page, 50),
  });

  const columns: Column<Match>[] = [
    {
      key: 'component',
      header: 'Component Package',
      sortable: true,
      render: (m) => (
        <div className="flex items-center gap-2">
          <Crosshair className="w-4 h-4 text-blue-400 shrink-0" />
          <span className="font-mono font-semibold text-soc-primary">
            {m.component?.name || '—'}
          </span>
        </div>
      ),
    },
    {
      key: 'version',
      header: 'Installed Version',
      render: (m) => (
        <span className="font-mono text-xs text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded border border-blue-500/20">
          {m.component?.version || '—'}
        </span>
      ),
    },
    {
      key: 'vulnerability',
      header: 'Vulnerability (CVE)',
      render: (m) => (
        <span className="font-mono text-xs font-semibold text-rose-400">
          {m.vulnerability?.cve_id || m.vulnerability_id.substring(0, 8)}
        </span>
      ),
    },
    {
      key: 'applicability',
      header: 'Applicability Verdict',
      sortable: true,
      render: (m) => <ApplicabilityBadge status={m.applicability} />,
    },
    {
      key: 'risk',
      header: 'Risk Posture',
      sortable: true,
      render: (m) => <RiskBadge level={m.risk_assessment?.risk_level || 'UNKNOWN'} />,
    },
    {
      key: 'review',
      header: 'Triage Status',
      render: (m) => (
        <ReviewBadge
          requiresReview={
            m.applicability?.toUpperCase() === 'REQUIRES_REVIEW' ||
            Boolean(m.risk_assessment?.requires_human_review)
          }
        />
      ),
    },
    {
      key: 'matched_at',
      header: 'Correlated At',
      sortable: true,
      render: (m) => <span className="font-mono text-xs">{formatDate(m.matched_at)}</span>,
    },
  ];

  if (isError) {
    return (
      <ErrorState
        title="Failed to Load Matches"
        description="Could not query vulnerability correlations from the engine database."
        requestId={(error as { requestId?: string })?.requestId}
        onRetry={() => refetch()}
      />
    );
  }

  const applicabilityOptions: { label: string; value: ApplicabilityType | '' }[] = [
    { label: 'All Applicability Verdicts', value: '' },
    { label: 'LIKELY_AFFECTED', value: 'LIKELY_AFFECTED' },
    { label: 'LIKELY_NOT_AFFECTED', value: 'LIKELY_NOT_AFFECTED' },
    { label: 'REQUIRES_REVIEW', value: 'REQUIRES_REVIEW' },
    { label: 'DETECTED', value: 'DETECTED' },
    { label: 'UNKNOWN', value: 'UNKNOWN' },
  ];

  return (
    <div className="space-y-6" data-testid="matches-page">
      <PageHeader
        title="Vulnerability Matches & Correlations"
        subtitle="Correlated findings between project dependencies and authoritative vulnerability advisories"
        actions={
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-soc-muted" />
            <select
              value={selectedApplicability}
              onChange={(e) => setSelectedApplicability(e.target.value)}
              className="px-3 py-1.5 text-xs font-mono rounded bg-soc-elevated border border-soc-border text-soc-primary focus:outline-none focus:border-blue-500"
              aria-label="Filter matches by applicability"
            >
              {applicabilityOptions.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
        }
      />

      <DataTable
        columns={columns}
        data={data?.items ?? []}
        keyExtractor={(m) => m.id}
        isLoading={isLoading}
        emptyTitle="No vulnerability matches found"
        emptyDescription="No dependencies matched the selected filters or no scans have detected matches yet."
        onRowClick={(m) => navigate(`/matches/${m.id}`)}
      />
    </div>
  );
};

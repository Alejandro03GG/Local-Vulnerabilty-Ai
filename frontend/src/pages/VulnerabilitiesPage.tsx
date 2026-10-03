import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { ShieldAlert, Flame } from 'lucide-react';
import { PageHeader } from '@/components/layout/PageHeader';
import { DataTable, Column } from '@/components/ui/DataTable';
import { ErrorState } from '@/components/ui/ErrorState';
import { vulnerabilitiesApi } from '@/services/api/vulnerabilities';
import { formatDate } from '@/lib/utils';
import type { Vulnerability } from '@/types';

export const VulnerabilitiesPage: React.FC = () => {
  const navigate = useNavigate();
  const [page] = useState(1);

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['vulnerabilities', page],
    queryFn: () => vulnerabilitiesApi.list(undefined, page, 50),
  });

  const columns: Column<Vulnerability>[] = [
    {
      key: 'cve_id',
      header: 'Identifier (CVE)',
      sortable: true,
      render: (v) => (
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
          <span className="font-mono font-semibold text-rose-400">{v.cve_id}</span>
        </div>
      ),
    },
    {
      key: 'vulnerability_name',
      header: 'Vulnerability Title',
      render: (v) => (
        <span className="text-xs text-soc-primary font-medium line-clamp-1">
          {v.vulnerability_name || v.short_description || 'Security Advisory'}
        </span>
      ),
    },
    {
      key: 'product',
      header: 'Vendor / Product',
      render: (v) => (
        <span className="font-mono text-xs text-soc-secondary">
          {v.vendor_project ? `${v.vendor_project} / ${v.product || '*'}` : v.product || '—'}
        </span>
      ),
    },
    {
      key: 'known_ransomware_use',
      header: 'CISA KEV / Exploitation',
      render: (v) =>
        v.known_ransomware_use ? (
          <span className="inline-flex items-center gap-1 font-mono text-[11px] text-red-400 font-bold px-2 py-0.5 rounded bg-red-500/10 border border-red-500/30">
            <Flame className="w-3 h-3 text-red-400" />
            KEV: {v.known_ransomware_use}
          </span>
        ) : (
          <span className="font-mono text-[11px] text-soc-muted">Standard</span>
        ),
    },
    {
      key: 'date_added',
      header: 'Cataloged',
      sortable: true,
      render: (v) => <span className="font-mono text-xs">{formatDate(v.date_added)}</span>,
    },
  ];

  if (isError) {
    return (
      <ErrorState
        title="Failed to Load Vulnerability Catalog"
        description="Could not query vulnerability catalog from database."
        requestId={(error as { requestId?: string })?.requestId}
        onRetry={() => refetch()}
      />
    );
  }

  return (
    <div className="space-y-6" data-testid="vulnerabilities-page">
      <PageHeader
        title="Vulnerability Intelligence Catalog"
        subtitle="Catalog of synchronized vulnerability advisories from OSV, NVD, and CISA KEV sources"
      />

      <DataTable
        columns={columns}
        data={data?.items ?? []}
        keyExtractor={(v) => v.id}
        isLoading={isLoading}
        emptyTitle="No vulnerabilities synchronized"
        emptyDescription="Ensure source intelligence sync is configured on the Sources page."
        onRowClick={(v) => navigate(`/vulnerabilities/${v.id}`)}
      />
    </div>
  );
};

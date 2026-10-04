import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { ShieldAlert, Flame } from 'lucide-react';
import { PageHeader } from '@/components/layout/PageHeader';
import { DataTable, Column } from '@/components/ui/DataTable';
import { ErrorState } from '@/components/ui/ErrorState';
import { vulnerabilitiesApi } from '@/services/api/vulnerabilities';
import { formatDate } from '@/lib/utils';
import { useI18n } from '@/i18n';
import { vulnerabilityDisplayId } from '@/lib/vulnerabilityId';
import type { Vulnerability } from '@/types';

export const VulnerabilitiesPage: React.FC = () => {
  const navigate = useNavigate();
  const { t, dateLocale } = useI18n();
  const [page] = useState(1);

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['vulnerabilities', page],
    queryFn: () => vulnerabilitiesApi.list(undefined, page, 50),
  });

  const columns: Column<Vulnerability>[] = [
    {
      key: 'cve_id',
      header: t('vulnerabilities.cols.identifier'),
      sortable: true,
      render: (v) => (
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
          <span className="font-mono font-semibold text-rose-400">{vulnerabilityDisplayId(v)}</span>
        </div>
      ),
    },
    {
      key: 'vulnerability_name',
      header: t('vulnerabilities.cols.title'),
      render: (v) => (
        <span className="text-xs text-soc-primary font-medium line-clamp-1">
          {v.vulnerability_name || v.short_description || t('vulnerabilities.advisoryFallback')}
        </span>
      ),
    },
    {
      key: 'product',
      header: t('vulnerabilities.cols.vendorProduct'),
      render: (v) => (
        <span className="font-mono text-xs text-soc-secondary">
          {v.vendor_project ? `${v.vendor_project} / ${v.product || '*'}` : v.product || '—'}
        </span>
      ),
    },
    {
      key: 'known_ransomware_use',
      header: t('vulnerabilities.cols.kev'),
      render: (v) =>
        v.known_ransomware_use ? (
          <span className="inline-flex items-center gap-1 font-mono text-[11px] text-red-400 font-bold px-2 py-0.5 rounded bg-red-500/10 border border-red-500/30">
            <Flame className="w-3 h-3 text-red-400" />
            {t('vulnerabilities.kev', { value: v.known_ransomware_use })}
          </span>
        ) : (
          <span className="font-mono text-[11px] text-soc-muted">
            {t('vulnerabilities.standard')}
          </span>
        ),
    },
    {
      key: 'date_added',
      header: t('vulnerabilities.cols.cataloged'),
      sortable: true,
      render: (v) => (
        <span className="font-mono text-xs">{formatDate(v.date_added, dateLocale)}</span>
      ),
    },
  ];

  if (isError) {
    return (
      <ErrorState
        title={t('vulnerabilities.errorTitle')}
        description={t('vulnerabilities.errorDescription')}
        requestId={(error as { requestId?: string })?.requestId}
        onRetry={() => refetch()}
      />
    );
  }

  return (
    <div className="space-y-6" data-testid="vulnerabilities-page">
      <PageHeader title={t('vulnerabilities.title')} subtitle={t('vulnerabilities.subtitle')} />

      <DataTable
        columns={columns}
        data={data?.items ?? []}
        keyExtractor={(v) => v.id}
        isLoading={isLoading}
        emptyTitle={t('vulnerabilities.emptyTitle')}
        emptyDescription={t('vulnerabilities.emptyDescription')}
        onRowClick={(v) => navigate(`/vulnerabilities/${v.id}`)}
      />
    </div>
  );
};

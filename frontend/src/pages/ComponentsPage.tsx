import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Package } from 'lucide-react';
import { PageHeader } from '@/components/layout/PageHeader';
import { DataTable, Column } from '@/components/ui/DataTable';
import { ErrorState } from '@/components/ui/ErrorState';
import { componentsApi } from '@/services/api/components';
import { formatDate } from '@/lib/utils';
import type { DetectedComponent } from '@/types';

export const ComponentsPage: React.FC = () => {
  const [page] = useState(1);

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['components', page],
    queryFn: () => componentsApi.list(undefined, page, 50),
  });

  const columns: Column<DetectedComponent>[] = [
    {
      key: 'name',
      header: 'Component Package',
      sortable: true,
      render: (c) => (
        <div className="flex items-center gap-2">
          <Package className="w-4 h-4 text-blue-400 shrink-0" />
          <span className="font-mono font-semibold text-soc-primary">{c.name}</span>
        </div>
      ),
    },
    {
      key: 'version',
      header: 'Installed Version',
      sortable: true,
      render: (c) => (
        <span className="font-mono text-xs text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded border border-blue-500/20">
          {c.version || '—'}
        </span>
      ),
    },
    {
      key: 'ecosystem',
      header: 'Ecosystem',
      sortable: true,
      render: (c) => (
        <span className="font-mono text-xs uppercase text-soc-secondary">{c.ecosystem}</span>
      ),
    },
    {
      key: 'dependency_type',
      header: 'Dependency Type',
      sortable: true,
      render: (c) => {
        const isDirect = c.is_direct ?? c.dependency_type === 'direct';
        return (
          <div className="flex flex-col gap-0.5">
            <span
              className={`font-mono text-[10px] font-bold px-1.5 py-0.5 rounded inline-block w-fit border ${
                isDirect
                  ? 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30'
                  : 'text-purple-400 bg-purple-500/10 border-purple-500/30'
              }`}
            >
              {isDirect ? 'DIRECT' : 'TRANSITIVE'}
            </span>
            {c.parent_name && !isDirect && (
              <span
                className="text-[10px] font-mono text-soc-muted truncate max-w-[120px]"
                title={`via ${c.parent_name}`}
              >
                via {c.parent_name}
              </span>
            )}
          </div>
        );
      },
    },
    {
      key: 'scope',
      header: 'Scope',
      render: (c) => (
        <span className="font-mono text-[11px] text-soc-secondary uppercase">
          {c.scope || 'runtime'}
        </span>
      ),
    },
    {
      key: 'source_file',
      header: 'Origin Source',
      render: (c) => {
        const originPath = c.lockfile_source || c.source_file;
        const filename = originPath.split('/').pop() || originPath;
        return (
          <span
            className="font-mono text-xs text-soc-muted truncate max-w-xs block"
            title={originPath}
          >
            {filename}
          </span>
        );
      },
    },
    {
      key: 'detected_at',
      header: 'Detected',
      sortable: true,
      render: (c) => <span className="font-mono text-xs">{formatDate(c.detected_at)}</span>,
    },
  ];

  if (isError) {
    return (
      <ErrorState
        title="Failed to Load Components"
        description="Could not query components from the inventory repository."
        requestId={(error as { requestId?: string })?.requestId}
        onRetry={() => refetch()}
      />
    );
  }

  return (
    <div className="space-y-6" data-testid="components-page">
      <PageHeader
        title="Software Components Inventory"
        subtitle="Catalog of all software dependencies detected across scanned target repositories"
      />

      <DataTable
        columns={columns}
        data={data?.items ?? []}
        keyExtractor={(c) => c.id}
        isLoading={isLoading}
        emptyTitle="No components cataloged"
        emptyDescription="Detected packages from scanned requirements.txt, pyproject.toml, and poetry.lock files will be cataloged here."
      />
    </div>
  );
};

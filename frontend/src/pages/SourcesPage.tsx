import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { RefreshCw, Database } from 'lucide-react';
import { PageHeader } from '@/components/layout/PageHeader';
import { SourceStatusBadge } from '@/components/badges/SourceStatusBadge';
import { ErrorState } from '@/components/ui/ErrorState';
import { LoadingState } from '@/components/ui/LoadingState';
import { useToast } from '@/hooks/useToast';
import { sourcesApi } from '@/services/api/sources';
import { formatDate } from '@/lib/utils';
import { useI18n } from '@/i18n';
import type { Source } from '@/types';

export const SourcesPage: React.FC = () => {
  const queryClient = useQueryClient();
  const { t, dateLocale } = useI18n();
  const { showToast } = useToast();
  const [syncingSourceId, setSyncingSourceId] = useState<string | null>(null);

  const {
    data: sources,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery({
    queryKey: ['sources'],
    queryFn: sourcesApi.list,
  });

  const syncMutation = useMutation({
    mutationFn: (sourceId: string) => sourcesApi.sync(sourceId),
    onMutate: (sourceId) => {
      setSyncingSourceId(sourceId);
    },
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['sources'] });
      queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] });
      setSyncingSourceId(null);
      if (result.success) {
        showToast(
          'success',
          t('sources.syncCompleted'),
          t('sources.syncCompletedDescription', {
            count: result.records_processed.toLocaleString(dateLocale),
            source: result.source_name,
          }),
        );
      } else {
        showToast(
          'error',
          t('sources.syncFailed'),
          result.error_message || t('sources.syncFailedFallback'),
        );
      }
    },
    onError: (err: { message: string }) => {
      setSyncingSourceId(null);
      showToast('error', t('sources.syncRequestFailed'), err.message);
    },
  });

  if (isLoading) {
    return <LoadingState message={t('sources.loading')} />;
  }

  if (isError) {
    return (
      <ErrorState
        title={t('sources.errorTitle')}
        description={t('sources.errorDescription')}
        requestId={(error as { requestId?: string })?.requestId}
        onRetry={() => refetch()}
      />
    );
  }

  return (
    <div className="space-y-6" data-testid="sources-page">
      <PageHeader title={t('sources.title')} subtitle={t('sources.subtitle')} />

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {sources && sources.length > 0 ? (
          sources.map((src: Source) => {
            const isSyncing = syncingSourceId === src.id;

            return (
              <div
                key={src.id}
                className="p-5 rounded-lg border border-soc-border bg-soc-surface flex flex-col justify-between space-y-4 hover:border-soc-border-light transition-colors"
                data-testid={`source-card-${src.id}`}
              >
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <Database className="w-5 h-5 text-blue-400" />
                      <h3 className="font-bold text-sm text-soc-primary">{src.name}</h3>
                    </div>
                    <SourceStatusBadge isAvailable={src.is_available} />
                  </div>

                  <div className="space-y-2 text-xs font-mono text-soc-secondary">
                    <div className="flex justify-between py-1 border-b border-soc-border/50">
                      <span className="text-soc-muted">{t('sources.type')}</span>
                      <span className="text-soc-primary uppercase">{src.source_type}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-soc-border/50">
                      <span className="text-soc-muted">{t('sources.cachedAdvisories')}</span>
                      <span className="text-soc-primary font-bold">
                        {src.record_count.toLocaleString(dateLocale)}
                      </span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-soc-border/50">
                      <span className="text-soc-muted">{t('sources.lastSynchronized')}</span>
                      <span className="text-soc-primary">
                        {formatDate(src.last_sync, dateLocale)}
                      </span>
                    </div>
                  </div>

                  {src.error_message && (
                    <div className="mt-3 p-2 rounded bg-rose-500/10 border border-rose-500/20 text-[11px] text-rose-300 font-mono">
                      {src.error_message}
                    </div>
                  )}
                </div>

                <div className="pt-3 border-t border-soc-border">
                  <button
                    onClick={() => syncMutation.mutate(src.id)}
                    disabled={isSyncing || syncMutation.isPending}
                    className="w-full flex items-center justify-center gap-2 py-2 px-3 text-xs font-semibold rounded bg-soc-elevated border border-soc-border hover:bg-soc-highlight text-soc-primary hover:text-white transition-colors disabled:opacity-50"
                  >
                    <RefreshCw
                      className={
                        isSyncing ? 'w-3.5 h-3.5 animate-spin text-blue-400' : 'w-3.5 h-3.5'
                      }
                    />
                    <span>{isSyncing ? t('sources.synchronizing') : t('sources.triggerSync')}</span>
                  </button>
                </div>
              </div>
            );
          })
        ) : (
          <div className="col-span-3 text-center py-12 border border-dashed border-soc-border rounded-lg text-soc-muted text-xs font-mono">
            {t('sources.empty')}
          </div>
        )}
      </div>
    </div>
  );
};

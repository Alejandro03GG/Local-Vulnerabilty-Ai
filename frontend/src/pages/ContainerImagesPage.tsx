import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { Boxes, Plus, FileCode, ShieldAlert, Cpu } from 'lucide-react';
import { PageHeader } from '@/components/layout/PageHeader';
import { DataTable, Column } from '@/components/ui/DataTable';
import { Metric } from '@/components/ui/Metric';
import { ErrorState } from '@/components/ui/ErrorState';
import {
  imagesApi,
  ContainerScanRequestPayload,
  DockerfileScanPayload,
} from '@/services/api/images';
import { formatDate } from '@/lib/utils';
import { useI18n } from '@/i18n';
import type { ContainerImage, DockerfileScanResult } from '@/types';

export const ContainerImagesPage: React.FC = () => {
  const navigate = useNavigate();
  const { t, dateLocale } = useI18n();
  const queryClient = useQueryClient();
  const [page] = useState(1);
  const [isScanModalOpen, setIsScanModalOpen] = useState(false);
  const [isDockerfileModalOpen, setIsDockerfileModalOpen] = useState(false);

  // Scan Archive Form State
  const [archivePath, setArchivePath] = useState('');
  const [reference, setReference] = useState('');
  const [noAi, setNoAi] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);

  // Dockerfile Scan State
  const [dockerfileContent, setDockerfileContent] = useState('');
  const [dockerfilePath, setDockerfilePath] = useState('');
  const [dockerfileResult, setDockerfileResult] = useState<DockerfileScanResult | null>(null);
  const [dockerfileError, setDockerfileError] = useState<string | null>(null);

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['container-images', page],
    queryFn: () => imagesApi.list(page, 50),
  });

  const scanMutation = useMutation({
    mutationFn: (payload: ContainerScanRequestPayload) => imagesApi.scanImage(payload),
    onSuccess: (newImage) => {
      queryClient.invalidateQueries({ queryKey: ['container-images'] });
      setIsScanModalOpen(false);
      setArchivePath('');
      setReference('');
      setScanError(null);
      navigate(`/images/${newImage.id}`);
    },
    onError: (err: unknown) => {
      const msg = (err as { message?: string })?.message || t('containerImages.errors.scanFailed');
      setScanError(msg);
    },
  });

  const dockerfileMutation = useMutation({
    mutationFn: (payload: DockerfileScanPayload) => imagesApi.scanDockerfile(payload),
    onSuccess: (result) => {
      setDockerfileResult(result);
      setDockerfileError(null);
    },
    onError: (err: unknown) => {
      const msg =
        (err as { message?: string })?.message || t('containerImages.errors.dockerfileFailed');
      setDockerfileError(msg);
    },
  });

  const handleScanSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!archivePath.trim()) {
      setScanError(t('containerImages.errors.archivePathRequired'));
      return;
    }
    setScanError(null);
    scanMutation.mutate({
      archive_path: archivePath.trim(),
      reference: reference.trim() || undefined,
      no_ai: noAi,
    });
  };

  const handleDockerfileSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!dockerfileContent.trim() && !dockerfilePath.trim()) {
      setDockerfileError(t('containerImages.errors.dockerfileInputRequired'));
      return;
    }
    setDockerfileError(null);
    dockerfileMutation.mutate({
      content: dockerfileContent.trim() || undefined,
      path: dockerfilePath.trim() || undefined,
    });
  };

  const images = data?.items ?? [];
  const totalLayers = images.reduce((acc, img) => acc + (img.layer_count || 0), 0);

  const columns: Column<ContainerImage>[] = [
    {
      key: 'reference',
      header: t('containerImages.cols.reference'),
      sortable: true,
      render: (img) => (
        <div>
          <div className="font-semibold text-xs text-blue-400 font-mono">{img.reference}</div>
          {img.digest && (
            <div
              className="text-[10px] text-soc-muted font-mono truncate max-w-[200px]"
              title={img.digest}
            >
              {img.digest}
            </div>
          )}
        </div>
      ),
    },
    {
      key: 'os',
      header: t('containerImages.cols.os'),
      sortable: true,
      render: (img) => (
        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-mono bg-soc-elevated text-soc-primary border border-soc-border">
          <Cpu className="w-3 h-3 text-soc-secondary" />
          {img.os}{' '}
          {img.os_version ? t('containerImages.osVersion', { version: img.os_version }) : ''}
        </span>
      ),
    },
    {
      key: 'architecture',
      header: t('containerImages.cols.arch'),
      sortable: true,
      render: (img) => (
        <span className="font-mono text-xs uppercase px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/20">
          {img.architecture}
        </span>
      ),
    },
    {
      key: 'layer_count',
      header: t('containerImages.cols.layers'),
      sortable: true,
      render: (img) => (
        <span className="font-mono text-xs font-semibold text-soc-primary">
          {t('containerImages.layersCount', { count: img.layer_count })}
        </span>
      ),
    },
    {
      key: 'source_type',
      header: t('containerImages.cols.format'),
      render: (img) => (
        <span className="text-[11px] font-mono text-soc-secondary uppercase">
          {img.source_type}
        </span>
      ),
    },
    {
      key: 'created_at',
      header: t('containerImages.cols.scannedAt'),
      sortable: true,
      render: (img) => (
        <span className="font-mono text-xs">{formatDate(img.created_at, dateLocale)}</span>
      ),
    },
  ];

  if (isError) {
    return (
      <ErrorState
        title={t('containerImages.errorTitle')}
        description={t('containerImages.errorDescription')}
        onRetry={() => refetch()}
      />
    );
  }

  return (
    <div className="space-y-6" data-testid="container-images-page">
      <PageHeader
        title={t('containerImages.title')}
        subtitle={t('containerImages.subtitle')}
        actions={
          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                setDockerfileResult(null);
                setDockerfileError(null);
                setIsDockerfileModalOpen(true);
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-soc-elevated hover:bg-soc-surface border border-soc-border text-soc-primary transition-colors"
            >
              <FileCode className="w-3.5 h-3.5 text-blue-400" />
              {t('containerImages.analyzeDockerfile')}
            </button>
            <button
              onClick={() => {
                setScanError(null);
                setIsScanModalOpen(true);
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-blue-600 hover:bg-blue-500 text-white shadow-sm transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              {t('containerImages.scanArchive')}
            </button>
          </div>
        }
      />

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Metric
          label={t('containerImages.metrics.images')}
          value={data?.total ?? 0}
          icon={Boxes}
          subtext={t('containerImages.metrics.imagesHint')}
        />
        <Metric
          label={t('containerImages.metrics.layers')}
          value={totalLayers}
          icon={Cpu}
          subtext={t('containerImages.metrics.layersHint')}
        />
        <Metric
          label={t('containerImages.metrics.mode')}
          value={t('containerImages.metrics.modeValue')}
          icon={Boxes}
          subtext={t('containerImages.metrics.modeHint')}
        />
        <Metric
          label={t('containerImages.metrics.engine')}
          value={t('containerImages.metrics.engineValue')}
          icon={Boxes}
          subtext={t('containerImages.metrics.engineHint')}
        />
      </div>

      {/* Table */}
      <DataTable
        columns={columns}
        data={images}
        keyExtractor={(img) => img.id}
        isLoading={isLoading}
        emptyTitle={t('containerImages.emptyTitle')}
        emptyDescription={t('containerImages.emptyDescription')}
        onRowClick={(img) => navigate(`/images/${img.id}`)}
      />

      {/* Scan Image Modal */}
      {isScanModalOpen && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-soc-surface border border-soc-border rounded-lg max-w-lg w-full p-6 shadow-xl space-y-4">
            <div className="flex items-center justify-between border-b border-soc-border pb-3">
              <h3 className="font-semibold text-sm text-soc-primary flex items-center gap-2">
                <Boxes className="w-4 h-4 text-blue-400" />
                {t('containerImages.scanModal.title')}
              </h3>
              <button
                onClick={() => setIsScanModalOpen(false)}
                className="text-soc-muted hover:text-soc-primary text-xs"
                aria-label={t('containerImages.scanModal.close')}
              >
                ✕
              </button>
            </div>

            {scanError && (
              <div className="p-3 bg-red-500/10 border border-red-500/30 rounded text-xs text-red-400 flex items-start gap-2">
                <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" />
                <span>{scanError}</span>
              </div>
            )}

            <form onSubmit={handleScanSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-soc-secondary mb-1">
                  {t('containerImages.scanModal.archivePath')}{' '}
                  <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  value={archivePath}
                  onChange={(e) => setArchivePath(e.target.value)}
                  placeholder={t('containerImages.scanModal.archivePathPlaceholder')}
                  className="w-full px-3 py-1.5 bg-soc-elevated border border-soc-border rounded text-xs text-soc-primary font-mono focus:outline-none focus:border-blue-500"
                  required
                />
                <p className="text-[11px] text-soc-muted mt-1">
                  {t('containerImages.scanModal.archivePathHint')}
                </p>
              </div>

              <div>
                <label className="block text-xs font-medium text-soc-secondary mb-1">
                  {t('containerImages.scanModal.reference')}
                </label>
                <input
                  type="text"
                  value={reference}
                  onChange={(e) => setReference(e.target.value)}
                  placeholder={t('containerImages.scanModal.referencePlaceholder')}
                  className="w-full px-3 py-1.5 bg-soc-elevated border border-soc-border rounded text-xs text-soc-primary font-mono focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="no-ai"
                  checked={noAi}
                  onChange={(e) => setNoAi(e.target.checked)}
                  className="rounded border-soc-border bg-soc-elevated text-blue-600 focus:ring-0"
                />
                <label htmlFor="no-ai" className="text-xs text-soc-secondary">
                  {t('containerImages.scanModal.noAi')}
                </label>
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-soc-border">
                <button
                  type="button"
                  onClick={() => setIsScanModalOpen(false)}
                  className="px-3 py-1.5 rounded text-xs text-soc-secondary hover:text-soc-primary transition-colors"
                >
                  {t('containerImages.scanModal.cancel')}
                </button>
                <button
                  type="submit"
                  disabled={scanMutation.isPending}
                  className="px-4 py-1.5 rounded text-xs font-medium bg-blue-600 hover:bg-blue-500 text-white transition-colors disabled:opacity-50"
                >
                  {scanMutation.isPending
                    ? t('containerImages.scanModal.inspecting')
                    : t('containerImages.scanModal.start')}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Dockerfile Scan Modal */}
      {isDockerfileModalOpen && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-soc-surface border border-soc-border rounded-lg max-w-2xl w-full p-6 shadow-xl space-y-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-soc-border pb-3">
              <h3 className="font-semibold text-sm text-soc-primary flex items-center gap-2">
                <FileCode className="w-4 h-4 text-blue-400" />
                {t('containerImages.dockerfileModal.title')}
              </h3>
              <button
                onClick={() => setIsDockerfileModalOpen(false)}
                className="text-soc-muted hover:text-soc-primary text-xs"
                aria-label={t('containerImages.dockerfileModal.close')}
              >
                ✕
              </button>
            </div>

            {dockerfileError && (
              <div className="p-3 bg-red-500/10 border border-red-500/30 rounded text-xs text-red-400 flex items-start gap-2">
                <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" />
                <span>{dockerfileError}</span>
              </div>
            )}

            {!dockerfileResult ? (
              <form onSubmit={handleDockerfileSubmit} className="space-y-4">
                <div>
                  <label className="block text-xs font-medium text-soc-secondary mb-1">
                    {t('containerImages.dockerfileModal.content')}
                  </label>
                  <textarea
                    rows={8}
                    value={dockerfileContent}
                    onChange={(e) => setDockerfileContent(e.target.value)}
                    placeholder="FROM alpine:3.19&#10;RUN apk add --no-cache curl&#10;COPY app/ /app/&#10;USER 10001"
                    className="w-full px-3 py-2 bg-soc-elevated border border-soc-border rounded text-xs text-soc-primary font-mono focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-soc-secondary mb-1">
                    {t('containerImages.dockerfileModal.path')}
                  </label>
                  <input
                    type="text"
                    value={dockerfilePath}
                    onChange={(e) => setDockerfilePath(e.target.value)}
                    placeholder={t('containerImages.dockerfileModal.pathPlaceholder')}
                    className="w-full px-3 py-1.5 bg-soc-elevated border border-soc-border rounded text-xs text-soc-primary font-mono focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div className="flex justify-end gap-2 pt-2 border-t border-soc-border">
                  <button
                    type="button"
                    onClick={() => setIsDockerfileModalOpen(false)}
                    className="px-3 py-1.5 rounded text-xs text-soc-secondary hover:text-soc-primary transition-colors"
                  >
                    {t('containerImages.dockerfileModal.cancel')}
                  </button>
                  <button
                    type="submit"
                    disabled={dockerfileMutation.isPending}
                    className="px-4 py-1.5 rounded text-xs font-medium bg-blue-600 hover:bg-blue-500 text-white transition-colors disabled:opacity-50"
                  >
                    {dockerfileMutation.isPending
                      ? t('containerImages.dockerfileModal.analyzing')
                      : t('containerImages.dockerfileModal.parse')}
                  </button>
                </div>
              </form>
            ) : (
              <div className="space-y-4 text-xs font-mono">
                <div className="p-3 bg-soc-elevated rounded border border-soc-border space-y-2">
                  <div className="text-soc-secondary font-semibold">
                    {t('containerImages.dockerfileModal.stages')}
                  </div>
                  <div className="space-y-1">
                    {dockerfileResult.stages.map((st) => (
                      <div key={st.index} className="flex items-center gap-2">
                        <span className="px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-400">
                          {t('containerImages.dockerfileModal.stage', {
                            index: st.index,
                            name: st.name || t('containerImages.dockerfileModal.unnamed'),
                          })}
                        </span>
                        <span className="text-soc-muted">
                          {t('containerImages.dockerfileModal.base', {
                            image: st.base_image ?? '',
                          })}
                        </span>
                        {st.is_runtime && (
                          <span className="px-1 py-0.2 bg-green-500/20 text-green-400 text-[10px] rounded">
                            {t('containerImages.dockerfileModal.runtime')}
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                <div className="p-3 bg-soc-elevated rounded border border-soc-border space-y-2">
                  <div className="text-soc-secondary font-semibold">
                    {t('containerImages.dockerfileModal.packages')}
                  </div>
                  {dockerfileResult.package_installations.length === 0 ? (
                    <div className="text-soc-muted">
                      {t('containerImages.dockerfileModal.noPackages')}
                    </div>
                  ) : (
                    <div className="space-y-1">
                      {dockerfileResult.package_installations.map((pkg, idx) => (
                        <div key={idx} className="flex items-center gap-2 text-soc-primary">
                          <span className="text-purple-400">
                            [
                            {String(
                              pkg.manager || t('containerImages.dockerfileModal.defaultManager'),
                            )}
                            ]
                          </span>
                          <span>{String(pkg.packages || '')}</span>
                          <span className="text-soc-muted">
                            {t('containerImages.dockerfileModal.line', {
                              line: String(pkg.line || ''),
                            })}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div className="p-3 bg-soc-elevated rounded border border-soc-border space-y-2">
                  <div className="text-soc-secondary font-semibold">
                    {t('containerImages.dockerfileModal.manifests')}
                  </div>
                  {dockerfileResult.dependency_manifests.length === 0 ? (
                    <div className="text-soc-muted">
                      {t('containerImages.dockerfileModal.noManifests')}
                    </div>
                  ) : (
                    <div className="flex flex-wrap gap-1">
                      {dockerfileResult.dependency_manifests.map((mf, i) => (
                        <span
                          key={i}
                          className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300"
                        >
                          {mf}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                <div className="flex justify-end gap-2 pt-2 border-t border-soc-border">
                  <button
                    onClick={() => setDockerfileResult(null)}
                    className="px-3 py-1.5 rounded text-xs bg-soc-elevated hover:bg-soc-surface border border-soc-border text-soc-primary"
                  >
                    {t('containerImages.dockerfileModal.analyzeAnother')}
                  </button>
                  <button
                    onClick={() => setIsDockerfileModalOpen(false)}
                    className="px-3 py-1.5 rounded text-xs bg-blue-600 hover:bg-blue-500 text-white"
                  >
                    {t('containerImages.dockerfileModal.done')}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

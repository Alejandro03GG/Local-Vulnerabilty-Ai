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
import type { ContainerImage, DockerfileScanResult } from '@/types';

export const ContainerImagesPage: React.FC = () => {
  const navigate = useNavigate();
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
      const msg =
        (err as { message?: string })?.message ||
        'Failed to inspect container image. Ensure the archive file exists and is readable.';
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
        (err as { message?: string })?.message ||
        'Failed to parse Dockerfile. Check syntax or file path.';
      setDockerfileError(msg);
    },
  });

  const handleScanSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!archivePath.trim()) {
      setScanError('Please enter a valid container archive path');
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
      setDockerfileError('Provide either Dockerfile content or an absolute file path');
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
      header: 'Image Reference',
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
      header: 'OS / Distribution',
      sortable: true,
      render: (img) => (
        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-mono bg-soc-elevated text-soc-primary border border-soc-border">
          <Cpu className="w-3 h-3 text-soc-secondary" />
          {img.os} {img.os_version ? `(${img.os_version})` : ''}
        </span>
      ),
    },
    {
      key: 'architecture',
      header: 'Arch',
      sortable: true,
      render: (img) => (
        <span className="font-mono text-xs uppercase px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/20">
          {img.architecture}
        </span>
      ),
    },
    {
      key: 'layer_count',
      header: 'Layers',
      sortable: true,
      render: (img) => (
        <span className="font-mono text-xs font-semibold text-soc-primary">
          {img.layer_count} layers
        </span>
      ),
    },
    {
      key: 'source_type',
      header: 'Format',
      render: (img) => (
        <span className="text-[11px] font-mono text-soc-secondary uppercase">
          {img.source_type}
        </span>
      ),
    },
    {
      key: 'created_at',
      header: 'Scanned At',
      sortable: true,
      render: (img) => <span className="font-mono text-xs">{formatDate(img.created_at)}</span>,
    },
  ];

  if (isError) {
    return (
      <ErrorState
        title="Failed to Load Container Images"
        description="Could not query container images from the local scanning engine."
        onRetry={() => refetch()}
      />
    );
  }

  return (
    <div className="space-y-6" data-testid="container-images-page">
      <PageHeader
        title="Container Images & Dockerfiles"
        subtitle="Static vulnerability and layer inspection for Docker/OCI tarballs without daemon execution"
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
              Analyze Dockerfile
            </button>
            <button
              onClick={() => {
                setScanError(null);
                setIsScanModalOpen(true);
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-blue-600 hover:bg-blue-500 text-white shadow-sm transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              Scan Image Archive
            </button>
          </div>
        }
      />

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Metric
          label="Scanned Images"
          value={data?.total ?? 0}
          icon={Boxes}
          subtext="Unique image archives inspected"
        />
        <Metric
          label="Total Layers"
          value={totalLayers}
          icon={Cpu}
          subtext="Immutable filesystem layers parsed"
        />
        <Metric
          label="Inspection Mode"
          value="Static Pure-Python"
          icon={Boxes}
          subtext="Zero workload runtime execution"
        />
        <Metric
          label="Active Engine"
          value="Determinism v1.0"
          icon={Boxes}
          subtext="Catalog + Multi-source Risk Engine"
        />
      </div>

      {/* Table */}
      <DataTable
        columns={columns}
        data={images}
        keyExtractor={(img) => img.id}
        isLoading={isLoading}
        emptyTitle="No Container Images Scanned Yet"
        emptyDescription="Execute an image scan on a local Docker/OCI tarball (.tar) to inspect OS packages and application dependencies."
        onRowClick={(img) => navigate(`/images/${img.id}`)}
      />

      {/* Scan Image Modal */}
      {isScanModalOpen && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-soc-surface border border-soc-border rounded-lg max-w-lg w-full p-6 shadow-xl space-y-4">
            <div className="flex items-center justify-between border-b border-soc-border pb-3">
              <h3 className="font-semibold text-sm text-soc-primary flex items-center gap-2">
                <Boxes className="w-4 h-4 text-blue-400" />
                Scan Container Archive
              </h3>
              <button
                onClick={() => setIsScanModalOpen(false)}
                className="text-soc-muted hover:text-soc-primary text-xs"
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
                  Archive Path (.tar) <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  value={archivePath}
                  onChange={(e) => setArchivePath(e.target.value)}
                  placeholder="/path/to/image.tar"
                  className="w-full px-3 py-1.5 bg-soc-elevated border border-soc-border rounded text-xs text-soc-primary font-mono focus:outline-none focus:border-blue-500"
                  required
                />
                <p className="text-[11px] text-soc-muted mt-1">
                  Absolute or relative path to a local Docker archive or OCI tarball.
                </p>
              </div>

              <div>
                <label className="block text-xs font-medium text-soc-secondary mb-1">
                  Custom Image Tag / Reference
                </label>
                <input
                  type="text"
                  value={reference}
                  onChange={(e) => setReference(e.target.value)}
                  placeholder="e.g. my-app:1.0 (defaults to archive tag)"
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
                  Disable optional local AI analysis (pure deterministic matching)
                </label>
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-soc-border">
                <button
                  type="button"
                  onClick={() => setIsScanModalOpen(false)}
                  className="px-3 py-1.5 rounded text-xs text-soc-secondary hover:text-soc-primary transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={scanMutation.isPending}
                  className="px-4 py-1.5 rounded text-xs font-medium bg-blue-600 hover:bg-blue-500 text-white transition-colors disabled:opacity-50"
                >
                  {scanMutation.isPending ? 'Inspecting Archive...' : 'Start Static Scan'}
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
                Static Dockerfile AST Analysis
              </h3>
              <button
                onClick={() => setIsDockerfileModalOpen(false)}
                className="text-soc-muted hover:text-soc-primary text-xs"
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
                    Dockerfile Content
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
                    Or Local File Path
                  </label>
                  <input
                    type="text"
                    value={dockerfilePath}
                    onChange={(e) => setDockerfilePath(e.target.value)}
                    placeholder="/path/to/Dockerfile"
                    className="w-full px-3 py-1.5 bg-soc-elevated border border-soc-border rounded text-xs text-soc-primary font-mono focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div className="flex justify-end gap-2 pt-2 border-t border-soc-border">
                  <button
                    type="button"
                    onClick={() => setIsDockerfileModalOpen(false)}
                    className="px-3 py-1.5 rounded text-xs text-soc-secondary hover:text-soc-primary transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={dockerfileMutation.isPending}
                    className="px-4 py-1.5 rounded text-xs font-medium bg-blue-600 hover:bg-blue-500 text-white transition-colors disabled:opacity-50"
                  >
                    {dockerfileMutation.isPending ? 'Analyzing AST...' : 'Parse & Analyze'}
                  </button>
                </div>
              </form>
            ) : (
              <div className="space-y-4 text-xs font-mono">
                <div className="p-3 bg-soc-elevated rounded border border-soc-border space-y-2">
                  <div className="text-soc-secondary font-semibold">Stages Detected:</div>
                  <div className="space-y-1">
                    {dockerfileResult.stages.map((st) => (
                      <div key={st.index} className="flex items-center gap-2">
                        <span className="px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-400">
                          Stage {st.index}: {st.name || 'unnamed'}
                        </span>
                        <span className="text-soc-muted">Base: {st.base_image}</span>
                        {st.is_runtime && (
                          <span className="px-1 py-0.2 bg-green-500/20 text-green-400 text-[10px] rounded">
                            RUNTIME
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                <div className="p-3 bg-soc-elevated rounded border border-soc-border space-y-2">
                  <div className="text-soc-secondary font-semibold">Package Installations:</div>
                  {dockerfileResult.package_installations.length === 0 ? (
                    <div className="text-soc-muted">
                      No explicit package manager commands detected.
                    </div>
                  ) : (
                    <div className="space-y-1">
                      {dockerfileResult.package_installations.map((pkg, idx) => (
                        <div key={idx} className="flex items-center gap-2 text-soc-primary">
                          <span className="text-purple-400">[{String(pkg.manager || 'run')}]</span>
                          <span>{String(pkg.packages || '')}</span>
                          <span className="text-soc-muted">(line {String(pkg.line || '')})</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div className="p-3 bg-soc-elevated rounded border border-soc-border space-y-2">
                  <div className="text-soc-secondary font-semibold">
                    Dependency Manifests Referenced:
                  </div>
                  {dockerfileResult.dependency_manifests.length === 0 ? (
                    <div className="text-soc-muted">No package manifests copied or referenced.</div>
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
                    Analyze Another
                  </button>
                  <button
                    onClick={() => setIsDockerfileModalOpen(false)}
                    className="px-3 py-1.5 rounded text-xs bg-blue-600 hover:bg-blue-500 text-white"
                  >
                    Done
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

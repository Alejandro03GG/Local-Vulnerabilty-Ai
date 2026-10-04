import React, { useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  Boxes,
  Layers,
  Package,
  ShieldAlert,
  GitFork,
  Cpu,
  ArrowLeft,
  ShieldCheck,
  Ban,
  CheckCircle,
} from 'lucide-react';
import { PageHeader } from '@/components/layout/PageHeader';
import { DataTable, Column } from '@/components/ui/DataTable';
import { Metric } from '@/components/ui/Metric';
import { ErrorState } from '@/components/ui/ErrorState';
import { LoadingState } from '@/components/ui/LoadingState';
import { ApplicabilityBadge } from '@/components/badges/ApplicabilityBadge';
import { RiskBadge } from '@/components/badges/RiskBadge';
import { imagesApi } from '@/services/api/images';
import { formatDate } from '@/lib/utils';
import { useI18n } from '@/i18n';
import { vulnerabilityDisplayId } from '@/lib/vulnerabilityId';
import type { ContainerComponent, ContainerLayer, Match } from '@/types';

type ActiveTab = 'overview' | 'layers' | 'components' | 'findings' | 'graph';

export const ImageDetailPage: React.FC = () => {
  const { imageId } = useParams<{ imageId: string }>();
  const navigate = useNavigate();
  const { t, dateLocale } = useI18n();
  const [activeTab, setActiveTab] = useState<ActiveTab>('overview');
  const [componentFilter, setComponentFilter] = useState<'all' | 'os' | 'app'>('all');

  const {
    data: image,
    isLoading: isImageLoading,
    isError: isImageError,
    refetch: refetchImage,
  } = useQuery({
    queryKey: ['container-image', imageId],
    queryFn: () => imagesApi.get(imageId!),
    enabled: Boolean(imageId),
  });

  const { data: layers = [], isLoading: isLayersLoading } = useQuery({
    queryKey: ['container-image-layers', imageId],
    queryFn: () => imagesApi.getLayers(imageId!),
    enabled: Boolean(imageId),
  });

  const { data: components = [], isLoading: isComponentsLoading } = useQuery({
    queryKey: ['container-image-components', imageId],
    queryFn: () => imagesApi.getComponents(imageId!),
    enabled: Boolean(imageId),
  });

  const { data: vulnerabilities = [], isLoading: isVulnsLoading } = useQuery({
    queryKey: ['container-image-vulns', imageId],
    queryFn: () => imagesApi.getVulnerabilities(imageId!),
    enabled: Boolean(imageId),
  });

  const { data: policyEval } = useQuery({
    queryKey: ['container-image-policy', imageId],
    queryFn: () => imagesApi.getPolicy(imageId!),
    enabled: Boolean(imageId),
    retry: false,
  });

  const { data: depGraph } = useQuery({
    queryKey: ['container-image-graph', imageId],
    queryFn: () => imagesApi.getDependencyGraph(imageId!),
    enabled: Boolean(imageId),
  });

  if (isImageLoading) {
    return <LoadingState message={t('imageDetail.loading')} />;
  }

  if (isImageError || !image) {
    return (
      <ErrorState
        title={t('imageDetail.errorTitle')}
        description={t('imageDetail.errorDescription')}
        onRetry={() => refetchImage()}
      />
    );
  }

  // Filter components
  const filteredComponents = components.filter((c) => {
    if (componentFilter === 'os') return c.component_type === 'os_package';
    if (componentFilter === 'app') return c.component_type !== 'os_package';
    return true;
  });

  // Layer table columns
  const layerColumns: Column<ContainerLayer>[] = [
    {
      key: 'layer_index',
      header: t('imageDetail.layerCols.index'),
      sortable: true,
      render: (l) => (
        <span className="font-mono text-xs font-semibold text-blue-400">#{l.layer_index}</span>
      ),
    },
    {
      key: 'digest',
      header: t('imageDetail.layerCols.digest'),
      render: (l) => (
        <span className="font-mono text-xs text-soc-secondary" title={l.digest}>
          {l.digest.substring(0, 19)}...
        </span>
      ),
    },
    {
      key: 'size_bytes',
      header: t('imageDetail.layerCols.size'),
      sortable: true,
      render: (l) => (
        <span className="font-mono text-xs text-soc-primary">
          {t('imageDetail.sizeMb', { size: (l.size_bytes / (1024 * 1024)).toFixed(2) })}
        </span>
      ),
    },
    {
      key: 'command',
      header: t('imageDetail.layerCols.command'),
      render: (l) => (
        <span
          className="font-mono text-xs text-soc-muted truncate max-w-md block"
          title={l.command || t('imageDetail.notAvailable')}
        >
          {l.command || t('imageDetail.notAvailable')}
        </span>
      ),
    },
  ];

  // Component table columns
  const componentColumns: Column<ContainerComponent>[] = [
    {
      key: 'name',
      header: t('imageDetail.componentCols.component'),
      sortable: true,
      render: (c) => (
        <div>
          <span className="font-semibold text-xs font-mono text-soc-primary">{c.name}</span>
          {c.is_direct === false && (
            <span className="ml-2 text-[10px] font-mono text-soc-muted uppercase px-1 py-0.2 bg-soc-elevated rounded">
              {t('imageDetail.transitive')}
            </span>
          )}
        </div>
      ),
    },
    {
      key: 'version',
      header: t('imageDetail.componentCols.version'),
      sortable: true,
      render: (c) => (
        <span className="font-mono text-xs text-blue-300">
          {c.version || t('imageDetail.unknownVersion')}
        </span>
      ),
    },
    {
      key: 'ecosystem',
      header: t('imageDetail.componentCols.ecosystem'),
      sortable: true,
      render: (c) => (
        <span className="font-mono text-xs uppercase px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/20">
          {c.ecosystem}
        </span>
      ),
    },
    {
      key: 'component_type',
      header: t('imageDetail.componentCols.type'),
      sortable: true,
      render: (c) => (
        <span
          className={`font-mono text-[11px] px-1.5 py-0.5 rounded ${
            c.component_type === 'os_package'
              ? 'bg-purple-500/10 text-purple-300 border border-purple-500/20'
              : 'bg-green-500/10 text-green-300 border border-green-500/20'
          }`}
        >
          {c.component_type === 'os_package'
            ? t('imageDetail.osPackage')
            : t('imageDetail.application')}
        </span>
      ),
    },
    {
      key: 'package_manager',
      header: t('imageDetail.componentCols.manager'),
      render: (c) => (
        <span className="font-mono text-xs text-soc-secondary">
          {c.package_manager ||
            (c.component_type === 'os_package'
              ? t('imageDetail.managerSystem')
              : t('imageDetail.managerManifest'))}
        </span>
      ),
    },
    {
      key: 'container_path',
      header: t('imageDetail.componentCols.location'),
      render: (c) => (
        <span
          className="font-mono text-xs text-soc-muted truncate max-w-[200px] block"
          title={c.container_path || ''}
        >
          {c.container_path || t('imageDetail.systemRootfs')}
        </span>
      ),
    },
  ];

  // Vulnerability table columns
  const vulnColumns: Column<Match>[] = [
    {
      key: 'vulnerability_id',
      header: t('imageDetail.vulnCols.vulnerability'),
      sortable: true,
      render: (m) => (
        <div>
          <span className="font-semibold text-xs font-mono text-red-400">
            {vulnerabilityDisplayId(m.vulnerability, m.vulnerability_id)}
          </span>
          {m.vulnerability?.known_ransomware_use?.toLowerCase() === 'known' && (
            <span className="ml-2 text-[10px] font-bold text-red-400 bg-red-500/20 border border-red-500/40 px-1 py-0.5 rounded">
              KEV
            </span>
          )}
        </div>
      ),
    },
    {
      key: 'component',
      header: t('imageDetail.vulnCols.package'),
      render: (m) => (
        <span className="font-mono text-xs text-soc-primary">
          {m.component?.name} @ {m.component?.version}
        </span>
      ),
    },
    {
      key: 'risk_level',
      header: t('imageDetail.vulnCols.risk'),
      sortable: true,
      render: (m) => <RiskBadge level={m.risk_assessment?.risk_level ?? 'unknown'} />,
    },
    {
      key: 'applicability',
      header: t('imageDetail.vulnCols.applicability'),
      sortable: true,
      render: (m) => <ApplicabilityBadge status={m.applicability} />,
    },
  ];

  return (
    <div className="space-y-6" data-testid="image-detail-page">
      {/* Top back navigation */}
      <div className="flex items-center gap-2">
        <Link
          to="/images"
          className="inline-flex items-center gap-1.5 text-xs text-soc-muted hover:text-soc-primary transition-colors font-mono"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          {t('imageDetail.backToImages')}
        </Link>
      </div>

      <PageHeader
        title={image.reference}
        subtitle={t('imageDetail.subtitle', {
          architecture: image.architecture,
          format: (image.source_type || 'tar').toUpperCase(),
        })}
        actions={
          image.scan_id ? (
            <button
              onClick={() => navigate(`/scans/${image.scan_id}`)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-soc-elevated hover:bg-soc-surface border border-soc-border text-soc-primary transition-colors font-mono"
            >
              <ShieldCheck className="w-3.5 h-3.5 text-blue-400" />
              {t('imageDetail.viewScan', { id: image.scan_id.substring(0, 8) })}
            </button>
          ) : undefined
        }
      />

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Metric
          label={t('imageDetail.metrics.layers')}
          value={image.layer_count}
          icon={Layers}
          subtext={t('imageDetail.metrics.layersHint')}
        />
        <Metric
          label={t('imageDetail.metrics.packages')}
          value={components.length}
          icon={Package}
          subtext={t('imageDetail.metrics.packagesHint', {
            os: components.filter((c) => c.component_type === 'os_package').length,
            app: components.filter((c) => c.component_type !== 'os_package').length,
          })}
        />
        <Metric
          label={t('imageDetail.metrics.vulnerabilities')}
          value={vulnerabilities.length}
          icon={ShieldAlert}
          subtext={t('imageDetail.metrics.vulnerabilitiesHint')}
        />
        <Metric
          label={t('imageDetail.metrics.compliance')}
          value={
            policyEval
              ? policyEval.has_violations
                ? t('imageDetail.metrics.violations', { count: policyEval.violations_count })
                : t('imageDetail.metrics.passed')
              : t('imageDetail.metrics.notEvaluated')
          }
          icon={policyEval && !policyEval.has_violations ? CheckCircle : Ban}
          subtext={policyEval?.policy_name || t('imageDetail.metrics.defaultPolicy')}
        />
      </div>

      {/* Tabs */}
      <div className="border-b border-soc-border flex gap-4 text-xs font-medium">
        <button
          onClick={() => setActiveTab('overview')}
          className={`pb-2.5 transition-colors border-b-2 font-mono flex items-center gap-1.5 ${
            activeTab === 'overview'
              ? 'border-blue-500 text-blue-400'
              : 'border-transparent text-soc-secondary hover:text-soc-primary'
          }`}
        >
          <Boxes className="w-3.5 h-3.5" />
          {t('imageDetail.tabs.overview')}
        </button>
        <button
          onClick={() => setActiveTab('layers')}
          className={`pb-2.5 transition-colors border-b-2 font-mono flex items-center gap-1.5 ${
            activeTab === 'layers'
              ? 'border-blue-500 text-blue-400'
              : 'border-transparent text-soc-secondary hover:text-soc-primary'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          {t('imageDetail.tabs.layers', { count: layers.length })}
        </button>
        <button
          onClick={() => setActiveTab('components')}
          className={`pb-2.5 transition-colors border-b-2 font-mono flex items-center gap-1.5 ${
            activeTab === 'components'
              ? 'border-blue-500 text-blue-400'
              : 'border-transparent text-soc-secondary hover:text-soc-primary'
          }`}
        >
          <Package className="w-3.5 h-3.5" />
          {t('imageDetail.tabs.components', { count: components.length })}
        </button>
        <button
          onClick={() => setActiveTab('findings')}
          className={`pb-2.5 transition-colors border-b-2 font-mono flex items-center gap-1.5 ${
            activeTab === 'findings'
              ? 'border-blue-500 text-blue-400'
              : 'border-transparent text-soc-secondary hover:text-soc-primary'
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5" />
          {t('imageDetail.tabs.findings', { count: vulnerabilities.length })}
        </button>
        <button
          onClick={() => setActiveTab('graph')}
          className={`pb-2.5 transition-colors border-b-2 font-mono flex items-center gap-1.5 ${
            activeTab === 'graph'
              ? 'border-blue-500 text-blue-400'
              : 'border-transparent text-soc-secondary hover:text-soc-primary'
          }`}
        >
          <GitFork className="w-3.5 h-3.5" />
          {t('imageDetail.tabs.graph')}
        </button>
      </div>

      {/* Tab: Overview */}
      {activeTab === 'overview' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-soc-surface border border-soc-border rounded-lg p-5 space-y-4">
            <h3 className="font-semibold text-xs text-soc-primary uppercase tracking-wider font-mono">
              {t('imageDetail.overview.specTitle')}
            </h3>
            <div className="space-y-3 font-mono text-xs">
              <div className="flex justify-between py-1 border-b border-soc-border/50">
                <span className="text-soc-muted">{t('imageDetail.overview.reference')}</span>
                <span className="text-soc-primary font-semibold">{image.reference}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-soc-border/50">
                <span className="text-soc-muted">{t('imageDetail.overview.digest')}</span>
                <span className="text-soc-secondary truncate max-w-xs" title={image.digest || ''}>
                  {image.digest || t('imageDetail.notAvailable')}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-soc-border/50">
                <span className="text-soc-muted">{t('imageDetail.overview.os')}</span>
                <span className="text-soc-primary">
                  {image.os} {image.os_version ? `v${image.os_version}` : ''}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-soc-border/50">
                <span className="text-soc-muted">{t('imageDetail.overview.architecture')}</span>
                <span className="text-soc-primary uppercase">{image.architecture}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-soc-border/50">
                <span className="text-soc-muted">{t('imageDetail.overview.sourcePath')}</span>
                <span className="text-soc-secondary truncate max-w-xs">
                  {image.source_path || t('imageDetail.notAvailable')}
                </span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-soc-muted">{t('imageDetail.overview.scannedAt')}</span>
                <span className="text-soc-primary">{formatDate(image.created_at, dateLocale)}</span>
              </div>
            </div>
          </div>

          <div className="bg-soc-surface border border-soc-border rounded-lg p-5 space-y-4">
            <h3 className="font-semibold text-xs text-soc-primary uppercase tracking-wider font-mono">
              {t('imageDetail.overview.policyTitle')}
            </h3>
            {policyEval ? (
              <div className="space-y-3 font-mono text-xs">
                <div className="flex justify-between py-1 border-b border-soc-border/50">
                  <span className="text-soc-muted">{t('imageDetail.overview.appliedPolicy')}</span>
                  <span className="text-blue-400 font-semibold">{policyEval.policy_name}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-soc-border/50">
                  <span className="text-soc-muted">
                    {t('imageDetail.overview.violationsLabel')}
                  </span>
                  <span
                    className={
                      policyEval.violations_count > 0 ? 'text-red-400 font-bold' : 'text-green-400'
                    }
                  >
                    {policyEval.violations_count}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-soc-border/50">
                  <span className="text-soc-muted">{t('imageDetail.overview.suppressions')}</span>
                  <span className="text-soc-primary">{policyEval.suppressed_count}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-soc-border/50">
                  <span className="text-soc-muted">{t('imageDetail.overview.requiresReview')}</span>
                  <span className="text-amber-400">{policyEval.requires_review_count}</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-soc-muted">{t('imageDetail.overview.exitCode')}</span>
                  <span className="text-soc-primary font-bold">
                    {t('imageDetail.codeValue', { code: policyEval.ci_exit_code })}
                  </span>
                </div>
              </div>
            ) : (
              <div className="text-xs text-soc-muted font-mono p-4 text-center">
                {t('imageDetail.overview.noPolicy')}
              </div>
            )}
          </div>

          {image.dockerfile_ast && (
            <div className="sm:col-span-2 bg-soc-surface border border-soc-border rounded-lg p-5 space-y-4">
              <h3 className="font-semibold text-xs text-soc-primary uppercase tracking-wider font-mono">
                Dockerfile AST
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
                <div>
                  <div className="text-soc-muted mb-1">Stages</div>
                  <div className="text-soc-primary">{image.dockerfile_ast.stages?.length ?? 0}</div>
                </div>
                <div>
                  <div className="text-soc-muted mb-1">Base images</div>
                  <div className="text-soc-primary">
                    {(image.dockerfile_ast.base_images || [])
                      .map((b) => (b as { raw?: string }).raw || JSON.stringify(b))
                      .join(', ') || '—'}
                  </div>
                </div>
                <div>
                  <div className="text-soc-muted mb-1">Package installations</div>
                  <div className="text-soc-primary">
                    {image.dockerfile_ast.package_installations?.length ?? 0}
                  </div>
                </div>
              </div>
              {(image.dockerfile_ast.package_installations || []).length > 0 && (
                <ul className="space-y-2 font-mono text-xs">
                  {image.dockerfile_ast.package_installations.map((inst, idx) => (
                    <li key={idx} className="border-b border-soc-border/40 pb-2">
                      <span className="text-blue-400">{String(inst.manager || 'pkg')}</span>
                      {': '}
                      <span className="text-soc-primary">
                        {Array.isArray(inst.packages) ? inst.packages.join(', ') : '—'}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>
      )}

      {/* Tab: Layers */}
      {activeTab === 'layers' && (
        <DataTable
          columns={layerColumns}
          data={layers}
          keyExtractor={(l) => l.id}
          isLoading={isLayersLoading}
          emptyTitle={t('imageDetail.layersEmptyTitle')}
          emptyDescription={t('imageDetail.layersEmptyDescription')}
        />
      )}

      {/* Tab: Components */}
      {activeTab === 'components' && (
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setComponentFilter('all')}
              className={`px-3 py-1 rounded text-xs font-mono transition-colors ${
                componentFilter === 'all'
                  ? 'bg-blue-600 text-white'
                  : 'bg-soc-elevated text-soc-secondary hover:text-soc-primary'
              }`}
            >
              {t('imageDetail.filterAll', { count: components.length })}
            </button>
            <button
              onClick={() => setComponentFilter('os')}
              className={`px-3 py-1 rounded text-xs font-mono transition-colors ${
                componentFilter === 'os'
                  ? 'bg-blue-600 text-white'
                  : 'bg-soc-elevated text-soc-secondary hover:text-soc-primary'
              }`}
            >
              {t('imageDetail.filterOs', {
                count: components.filter((c) => c.component_type === 'os_package').length,
              })}
            </button>
            <button
              onClick={() => setComponentFilter('app')}
              className={`px-3 py-1 rounded text-xs font-mono transition-colors ${
                componentFilter === 'app'
                  ? 'bg-blue-600 text-white'
                  : 'bg-soc-elevated text-soc-secondary hover:text-soc-primary'
              }`}
            >
              {t('imageDetail.filterApp', {
                count: components.filter((c) => c.component_type !== 'os_package').length,
              })}
            </button>
          </div>

          <DataTable
            columns={componentColumns}
            data={filteredComponents}
            keyExtractor={(c) => c.id}
            isLoading={isComponentsLoading}
            emptyTitle={t('imageDetail.componentsEmptyTitle')}
            emptyDescription={t('imageDetail.componentsEmptyDescription')}
          />
        </div>
      )}

      {/* Tab: Findings */}
      {activeTab === 'findings' && (
        <DataTable
          columns={vulnColumns}
          data={vulnerabilities}
          keyExtractor={(m) => m.id}
          isLoading={isVulnsLoading}
          emptyTitle={t('imageDetail.findingsEmptyTitle')}
          emptyDescription={t('imageDetail.findingsEmptyDescription')}
          onRowClick={(m) => navigate(`/matches/${m.id}`)}
        />
      )}

      {/* Tab: Dependency Graph */}
      {activeTab === 'graph' && (
        <div className="bg-soc-surface border border-soc-border rounded-lg p-5 space-y-4">
          <h3 className="font-semibold text-xs text-soc-primary uppercase tracking-wider font-mono">
            {t('imageDetail.graph.title')}
          </h3>
          <p className="text-xs text-soc-muted">{t('imageDetail.graph.description')}</p>

          <div className="p-4 bg-soc-elevated rounded border border-soc-border font-mono text-xs space-y-3">
            <div className="flex items-center gap-2 text-blue-400 font-bold">
              <Boxes className="w-4 h-4" />
              <span>{t('imageDetail.graph.image', { reference: image.reference })}</span>
            </div>

            <div className="ml-6 pl-3 border-l-2 border-soc-border space-y-2">
              <div className="flex items-center gap-2 text-purple-300">
                <Cpu className="w-3.5 h-3.5" />
                <span>
                  {t('imageDetail.graph.os', {
                    os: image.os,
                    count: components.filter((c) => c.component_type === 'os_package').length,
                  })}
                </span>
              </div>

              {depGraph?.edges && depGraph.edges.length > 0 ? (
                <div className="ml-6 pl-3 border-l-2 border-soc-border space-y-1">
                  <div className="text-soc-secondary font-semibold">
                    {t('imageDetail.graph.edges')}
                  </div>
                  {depGraph.edges.slice(0, 20).map((edge, idx) => (
                    <div key={idx} className="text-soc-muted">
                      {String(edge.parent_name || t('imageDetail.graph.root'))} ──▶{' '}
                      <span className="text-green-300">{String(edge.child_name || '')}</span>{' '}
                      {edge.requirement ? `(${String(edge.requirement)})` : ''}
                    </div>
                  ))}
                  {depGraph.edges.length > 20 && (
                    <div className="text-soc-muted italic">
                      {t('imageDetail.graph.more', { count: depGraph.edges.length - 20 })}
                    </div>
                  )}
                </div>
              ) : (
                <div className="ml-6 text-soc-muted">{t('imageDetail.graph.allDirect')}</div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

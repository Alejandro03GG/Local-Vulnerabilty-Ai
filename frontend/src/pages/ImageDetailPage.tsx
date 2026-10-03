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
import type { ContainerComponent, ContainerLayer, Match } from '@/types';

type ActiveTab = 'overview' | 'layers' | 'components' | 'findings' | 'graph';

export const ImageDetailPage: React.FC = () => {
  const { imageId } = useParams<{ imageId: string }>();
  const navigate = useNavigate();
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
    return <LoadingState message="Inspecting container layers and components..." />;
  }

  if (isImageError || !image) {
    return (
      <ErrorState
        title="Failed to Load Container Image"
        description="Could not retrieve persisted container image metadata."
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
      header: 'Index',
      sortable: true,
      render: (l) => (
        <span className="font-mono text-xs font-semibold text-blue-400">#{l.layer_index}</span>
      ),
    },
    {
      key: 'digest',
      header: 'Layer Digest',
      render: (l) => (
        <span className="font-mono text-xs text-soc-secondary" title={l.digest}>
          {l.digest.substring(0, 19)}...
        </span>
      ),
    },
    {
      key: 'size_bytes',
      header: 'Size',
      sortable: true,
      render: (l) => (
        <span className="font-mono text-xs text-soc-primary">
          {(l.size_bytes / (1024 * 1024)).toFixed(2)} MB
        </span>
      ),
    },
    {
      key: 'command',
      header: 'Build Command / Instruction',
      render: (l) => (
        <span
          className="font-mono text-xs text-soc-muted truncate max-w-md block"
          title={l.command || 'N/A'}
        >
          {l.command || 'N/A'}
        </span>
      ),
    },
  ];

  // Component table columns
  const componentColumns: Column<ContainerComponent>[] = [
    {
      key: 'name',
      header: 'Component',
      sortable: true,
      render: (c) => (
        <div>
          <span className="font-semibold text-xs font-mono text-soc-primary">{c.name}</span>
          {c.is_direct === false && (
            <span className="ml-2 text-[10px] font-mono text-soc-muted uppercase px-1 py-0.2 bg-soc-elevated rounded">
              Transitive
            </span>
          )}
        </div>
      ),
    },
    {
      key: 'version',
      header: 'Version',
      sortable: true,
      render: (c) => (
        <span className="font-mono text-xs text-blue-300">{c.version || 'unknown'}</span>
      ),
    },
    {
      key: 'ecosystem',
      header: 'Ecosystem',
      sortable: true,
      render: (c) => (
        <span className="font-mono text-xs uppercase px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/20">
          {c.ecosystem}
        </span>
      ),
    },
    {
      key: 'component_type',
      header: 'Type',
      sortable: true,
      render: (c) => (
        <span
          className={`font-mono text-[11px] px-1.5 py-0.5 rounded ${
            c.component_type === 'os_package'
              ? 'bg-purple-500/10 text-purple-300 border border-purple-500/20'
              : 'bg-green-500/10 text-green-300 border border-green-500/20'
          }`}
        >
          {c.component_type === 'os_package' ? 'OS Package' : 'Application'}
        </span>
      ),
    },
    {
      key: 'package_manager',
      header: 'Manager',
      render: (c) => (
        <span className="font-mono text-xs text-soc-secondary">
          {c.package_manager || (c.component_type === 'os_package' ? 'system' : 'manifest')}
        </span>
      ),
    },
    {
      key: 'container_path',
      header: 'Container Location',
      render: (c) => (
        <span
          className="font-mono text-xs text-soc-muted truncate max-w-[200px] block"
          title={c.container_path || ''}
        >
          {c.container_path || 'system rootfs'}
        </span>
      ),
    },
  ];

  // Vulnerability table columns
  const vulnColumns: Column<Match>[] = [
    {
      key: 'vulnerability_id',
      header: 'Vulnerability',
      sortable: true,
      render: (m) => (
        <div>
          <span className="font-semibold text-xs font-mono text-red-400">
            {m.vulnerability?.cve_id || m.vulnerability_id}
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
      header: 'Affected Package',
      render: (m) => (
        <span className="font-mono text-xs text-soc-primary">
          {m.component?.name} @ {m.component?.version}
        </span>
      ),
    },
    {
      key: 'risk_level',
      header: 'Technical Risk',
      sortable: true,
      render: (m) => <RiskBadge level={m.risk_assessment?.risk_level ?? 'unknown'} />,
    },
    {
      key: 'applicability',
      header: 'Applicability',
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
          Back to Images
        </Link>
      </div>

      <PageHeader
        title={image.reference}
        subtitle={`Static container inspection • Architecture: ${image.architecture} • Format: ${(image.source_type || 'tar').toUpperCase()}`}
        actions={
          image.scan_id ? (
            <button
              onClick={() => navigate(`/scans/${image.scan_id}`)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-soc-elevated hover:bg-soc-surface border border-soc-border text-soc-primary transition-colors font-mono"
            >
              <ShieldCheck className="w-3.5 h-3.5 text-blue-400" />
              View Underlying Scan #{image.scan_id.substring(0, 8)}
            </button>
          ) : undefined
        }
      />

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Metric
          label="Filesystem Layers"
          value={image.layer_count}
          icon={Layers}
          subtext="Immutable tar archive layers"
        />
        <Metric
          label="Total Packages"
          value={components.length}
          icon={Package}
          subtext={`${components.filter((c) => c.component_type === 'os_package').length} OS, ${
            components.filter((c) => c.component_type !== 'os_package').length
          } App`}
        />
        <Metric
          label="Vulnerabilities"
          value={vulnerabilities.length}
          icon={ShieldAlert}
          subtext="Matched against catalog & sources"
        />
        <Metric
          label="Policy Compliance"
          value={
            policyEval
              ? policyEval.has_violations
                ? `${policyEval.violations_count} Violations`
                : 'PASSED'
              : 'Not Evaluated'
          }
          icon={policyEval && !policyEval.has_violations ? CheckCircle : Ban}
          subtext={policyEval?.policy_name || 'Default Security Policy'}
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
          Overview
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
          Layers ({layers.length})
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
          Components ({components.length})
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
          Findings ({vulnerabilities.length})
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
          Dependency Graph
        </button>
      </div>

      {/* Tab: Overview */}
      {activeTab === 'overview' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-soc-surface border border-soc-border rounded-lg p-5 space-y-4">
            <h3 className="font-semibold text-xs text-soc-primary uppercase tracking-wider font-mono">
              Image Specification
            </h3>
            <div className="space-y-3 font-mono text-xs">
              <div className="flex justify-between py-1 border-b border-soc-border/50">
                <span className="text-soc-muted">Reference</span>
                <span className="text-soc-primary font-semibold">{image.reference}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-soc-border/50">
                <span className="text-soc-muted">Digest</span>
                <span className="text-soc-secondary truncate max-w-xs" title={image.digest || ''}>
                  {image.digest || 'N/A'}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-soc-border/50">
                <span className="text-soc-muted">Operating System</span>
                <span className="text-soc-primary">
                  {image.os} {image.os_version ? `v${image.os_version}` : ''}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-soc-border/50">
                <span className="text-soc-muted">Architecture</span>
                <span className="text-soc-primary uppercase">{image.architecture}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-soc-border/50">
                <span className="text-soc-muted">Source Path</span>
                <span className="text-soc-secondary truncate max-w-xs">
                  {image.source_path || 'N/A'}
                </span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-soc-muted">Scanned At</span>
                <span className="text-soc-primary">{formatDate(image.created_at)}</span>
              </div>
            </div>
          </div>

          <div className="bg-soc-surface border border-soc-border rounded-lg p-5 space-y-4">
            <h3 className="font-semibold text-xs text-soc-primary uppercase tracking-wider font-mono">
              Policy & Compliance Status
            </h3>
            {policyEval ? (
              <div className="space-y-3 font-mono text-xs">
                <div className="flex justify-between py-1 border-b border-soc-border/50">
                  <span className="text-soc-muted">Applied Policy</span>
                  <span className="text-blue-400 font-semibold">{policyEval.policy_name}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-soc-border/50">
                  <span className="text-soc-muted">Violations</span>
                  <span
                    className={
                      policyEval.violations_count > 0 ? 'text-red-400 font-bold' : 'text-green-400'
                    }
                  >
                    {policyEval.violations_count}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-soc-border/50">
                  <span className="text-soc-muted">Active Suppressions</span>
                  <span className="text-soc-primary">{policyEval.suppressed_count}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-soc-border/50">
                  <span className="text-soc-muted">Requires Review</span>
                  <span className="text-amber-400">{policyEval.requires_review_count}</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-soc-muted">CI/CD Gate Exit Code</span>
                  <span className="text-soc-primary font-bold">code {policyEval.ci_exit_code}</span>
                </div>
              </div>
            ) : (
              <div className="text-xs text-soc-muted font-mono p-4 text-center">
                No policy evaluation recorded for this scan.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab: Layers */}
      {activeTab === 'layers' && (
        <DataTable
          columns={layerColumns}
          data={layers}
          keyExtractor={(l) => l.id}
          isLoading={isLayersLoading}
          emptyTitle="No Layers Found"
          emptyDescription="No immutable layers were recorded for this container archive."
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
              All ({components.length})
            </button>
            <button
              onClick={() => setComponentFilter('os')}
              className={`px-3 py-1 rounded text-xs font-mono transition-colors ${
                componentFilter === 'os'
                  ? 'bg-blue-600 text-white'
                  : 'bg-soc-elevated text-soc-secondary hover:text-soc-primary'
              }`}
            >
              OS Packages ({components.filter((c) => c.component_type === 'os_package').length})
            </button>
            <button
              onClick={() => setComponentFilter('app')}
              className={`px-3 py-1 rounded text-xs font-mono transition-colors ${
                componentFilter === 'app'
                  ? 'bg-blue-600 text-white'
                  : 'bg-soc-elevated text-soc-secondary hover:text-soc-primary'
              }`}
            >
              Application Dependencies (
              {components.filter((c) => c.component_type !== 'os_package').length})
            </button>
          </div>

          <DataTable
            columns={componentColumns}
            data={filteredComponents}
            keyExtractor={(c) => c.id}
            isLoading={isComponentsLoading}
            emptyTitle="No Components Match Filter"
            emptyDescription="No components found in this container image matching the selected filter."
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
          emptyTitle="Zero Vulnerabilities Detected"
          emptyDescription="This container image has no matching vulnerabilities in the local catalog."
          onRowClick={(m) => navigate(`/matches/${m.id}`)}
        />
      )}

      {/* Tab: Dependency Graph */}
      {activeTab === 'graph' && (
        <div className="bg-soc-surface border border-soc-border rounded-lg p-5 space-y-4">
          <h3 className="font-semibold text-xs text-soc-primary uppercase tracking-wider font-mono">
            Container Dependency Topology
          </h3>
          <p className="text-xs text-soc-muted">
            Hierarchical representation of base image, operating system packages, application
            manifests, and dependency chains.
          </p>

          <div className="p-4 bg-soc-elevated rounded border border-soc-border font-mono text-xs space-y-3">
            <div className="flex items-center gap-2 text-blue-400 font-bold">
              <Boxes className="w-4 h-4" />
              <span>Container Image: {image.reference}</span>
            </div>

            <div className="ml-6 pl-3 border-l-2 border-soc-border space-y-2">
              <div className="flex items-center gap-2 text-purple-300">
                <Cpu className="w-3.5 h-3.5" />
                <span>
                  Operating System: {image.os} (
                  {components.filter((c) => c.component_type === 'os_package').length} packages
                  detected)
                </span>
              </div>

              {depGraph?.edges && depGraph.edges.length > 0 ? (
                <div className="ml-6 pl-3 border-l-2 border-soc-border space-y-1">
                  <div className="text-soc-secondary font-semibold">Resolved Dependency Edges:</div>
                  {depGraph.edges.slice(0, 20).map((edge, idx) => (
                    <div key={idx} className="text-soc-muted">
                      {String(edge.parent_name || 'root')} ──▶{' '}
                      <span className="text-green-300">{String(edge.child_name || '')}</span>{' '}
                      {edge.requirement ? `(${String(edge.requirement)})` : ''}
                    </div>
                  ))}
                  {depGraph.edges.length > 20 && (
                    <div className="text-soc-muted italic">
                      + {depGraph.edges.length - 20} more dependency relations
                    </div>
                  )}
                </div>
              ) : (
                <div className="ml-6 text-soc-muted">
                  All components operating as direct or base image dependencies.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

import React from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Download } from 'lucide-react';
import { PageHeader } from '@/components/layout/PageHeader';
import { DataTable, Column } from '@/components/ui/DataTable';
import { ScanStatusBadge } from '@/components/badges/ScanStatusBadge';
import { ApplicabilityBadge } from '@/components/badges/ApplicabilityBadge';
import { RiskBadge } from '@/components/badges/RiskBadge';
import { Metric } from '@/components/ui/Metric';
import { ErrorState } from '@/components/ui/ErrorState';
import { LoadingState } from '@/components/ui/LoadingState';
import { scansApi } from '@/services/api/scans';
import { policyApi } from '@/services/api/policy';
import { formatDate, formatDuration } from '@/lib/utils';
import type { Match } from '@/types';

export const ScanDetailPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();

  const handleExport = (format: 'sarif' | 'cyclonedx' | 'spdx') => {
    if (!scanId) return;
    const url = scansApi.getExportUrl(scanId, format);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', '');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const {
    data: scan,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => scansApi.get(scanId!),
    enabled: Boolean(scanId),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === 'running' || status === 'pending' ? 2000 : false;
    },
  });

  const { data: policyEval } = useQuery({
    queryKey: ['scan-policy', scanId],
    queryFn: () => policyApi.getScanPolicy(scanId!),
    enabled: Boolean(scanId),
    retry: false,
  });

  if (isLoading) {
    return <LoadingState message="Retrieving scan execution and match telemetry..." />;
  }

  if (isError || !scan) {
    return (
      <ErrorState
        title="Scan Not Found"
        description="The requested scan execution could not be located."
        requestId={(error as { requestId?: string })?.requestId}
        onRetry={() => refetch()}
      />
    );
  }

  const matches = scan.matches ?? [];

  const matchColumns: Column<Match>[] = [
    {
      key: 'component',
      header: 'Component',
      render: (m) => (
        <span className="font-mono text-xs font-semibold text-soc-primary">
          {m.component?.name || '—'}
        </span>
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
      header: 'Vulnerability Advisory',
      render: (m) => (
        <span className="font-mono text-xs font-semibold text-rose-400">
          {m.vulnerability?.cve_id || m.vulnerability_id.substring(0, 8)}
        </span>
      ),
    },
    {
      key: 'applicability',
      header: 'Applicability',
      render: (m) => <ApplicabilityBadge status={m.applicability} />,
    },
    {
      key: 'risk',
      header: 'Risk Level',
      render: (m) => <RiskBadge level={m.risk_assessment?.risk_level || 'UNKNOWN'} />,
    },
    {
      key: 'review',
      header: 'Human Review',
      render: (m) =>
        m.risk_assessment?.requires_human_review || m.applicability === 'REQUIRES_REVIEW' ? (
          <span className="text-[11px] font-mono text-amber-400 font-semibold px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/30">
            REQUIRED
          </span>
        ) : (
          <span className="text-[11px] font-mono text-soc-muted">None</span>
        ),
    },
  ];

  return (
    <div className="space-y-6" data-testid="scan-detail-page">
      <PageHeader
        title={`Scan Execution: ${scan.id.substring(0, 8)}`}
        subtitle={`Associated with Project ${scan.project_id.substring(0, 8)}`}
        backTo="/scans"
        badge={<ScanStatusBadge status={scan.status} />}
        actions={
          <div className="flex items-center gap-1.5 bg-soc-surface p-1 rounded-lg border border-soc-border">
            <span className="text-[11px] font-mono text-soc-muted px-2 flex items-center gap-1">
              <Download className="w-3.5 h-3.5 text-soc-secondary" />
              Export:
            </span>
            <button
              onClick={() => handleExport('sarif')}
              className="px-2.5 py-1 text-xs font-mono font-medium rounded bg-soc-elevated hover:bg-soc-highlight text-soc-primary border border-soc-border transition-colors hover:text-white"
              title="Export scan results in OASIS SARIF 2.1.0 format"
              data-testid="export-sarif-btn"
            >
              SARIF
            </button>
            <button
              onClick={() => handleExport('cyclonedx')}
              className="px-2.5 py-1 text-xs font-mono font-medium rounded bg-soc-elevated hover:bg-soc-highlight text-soc-primary border border-soc-border transition-colors hover:text-white"
              title="Export software bill of materials in CycloneDX 1.5 JSON format"
              data-testid="export-cyclonedx-btn"
            >
              CycloneDX
            </button>
            <button
              onClick={() => handleExport('spdx')}
              className="px-2.5 py-1 text-xs font-mono font-medium rounded bg-soc-elevated hover:bg-soc-highlight text-soc-primary border border-soc-border transition-colors hover:text-white"
              title="Export software bill of materials in SPDX 2.3 JSON format"
              data-testid="export-spdx-btn"
            >
              SPDX
            </button>
          </div>
        }
      />

      {/* Error banner if scan failed */}
      {scan.error && (
        <div className="p-4 rounded-lg bg-rose-950/20 border border-rose-500/30 text-rose-300 text-xs font-mono">
          <strong className="block mb-1">SCAN EXECUTION ERROR</strong>
          {scan.error}
        </div>
      )}

      {/* Policy & Compliance Evaluation (Etapa 16) */}
      {policyEval && (
        <div
          className="p-5 rounded-lg bg-soc-surface border border-soc-border space-y-4"
          data-testid="policy-compliance-card"
        >
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-soc-border pb-3">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold uppercase tracking-wider text-soc-muted">
                  Policy & Compliance
                </span>
                <span
                  className={`text-xs font-mono font-bold px-2 py-0.5 rounded border uppercase ${
                    policyEval.status === 'VIOLATION'
                      ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                      : policyEval.status === 'REQUIRES_REVIEW'
                        ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                        : policyEval.status === 'SUPPRESSED'
                          ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
                          : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                  }`}
                >
                  {policyEval.status}
                </span>
                <span
                  className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                    policyEval.ci_exit_code === 0
                      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                      : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                  }`}
                >
                  CI EXIT {policyEval.ci_exit_code} (
                  {policyEval.ci_exit_code === 0 ? 'PASS' : 'FAIL'})
                </span>
              </div>
              <p className="text-xs text-soc-secondary mt-1">
                Evaluated against policy{' '}
                <strong className="text-soc-primary font-mono">{policyEval.policy_name}</strong>
              </p>
            </div>
            <div className="flex items-center gap-4 text-xs font-mono">
              <div>
                <span className="text-soc-muted">Violations: </span>
                <span className="text-rose-400 font-bold">{policyEval.violations_count}</span>
              </div>
              <div>
                <span className="text-soc-muted">Suppressed: </span>
                <span className="text-cyan-400 font-bold">{policyEval.suppressed_count}</span>
              </div>
              <div>
                <span className="text-soc-muted">Requires Review: </span>
                <span className="text-amber-400 font-bold">{policyEval.requires_review_count}</span>
              </div>
              <div>
                <span className="text-soc-muted">Allowed: </span>
                <span className="text-emerald-400 font-bold">{policyEval.allowed_count}</span>
              </div>
            </div>
          </div>

          {/* Violations List if any */}
          {policyEval.violations && policyEval.violations.length > 0 && (
            <div className="space-y-2">
              <span className="text-[11px] font-bold uppercase tracking-wider text-rose-400 block">
                Policy Violations ({policyEval.violations.length})
              </span>
              <div className="border border-rose-500/20 rounded-md overflow-hidden bg-rose-950/10 divide-y divide-rose-500/10 text-xs font-mono">
                {policyEval.violations.map((v, i) => (
                  <div key={i} className="p-2.5 flex items-center justify-between gap-2">
                    <div>
                      <span className="text-soc-primary font-semibold">
                        {v.component_name} @ {v.component_version}
                      </span>
                      <span className="text-rose-400 ml-2">[{v.vulnerability_id}]</span>
                      <div className="text-[11px] text-soc-secondary mt-0.5">{v.reason}</div>
                    </div>
                    <div className="text-right text-[10px] text-amber-400">
                      Rules: {v.matched_rules?.join(', ') || 'threshold'}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Applied Suppressions if any */}
          {policyEval.suppressions_applied && policyEval.suppressions_applied.length > 0 && (
            <div className="space-y-2">
              <span className="text-[11px] font-bold uppercase tracking-wider text-cyan-400 block">
                Applied Suppressions ({policyEval.suppressions_applied.length})
              </span>
              <div className="border border-cyan-500/20 rounded-md overflow-hidden bg-cyan-950/10 divide-y divide-cyan-500/10 text-xs font-mono">
                {policyEval.suppressions_applied.map((s, i) => (
                  <div key={i} className="p-2.5 flex items-center justify-between gap-2">
                    <div>
                      <span className="text-cyan-400 font-semibold">
                        {String(s.suppression_id || '').substring(0, 8)}
                      </span>
                      <span className="text-soc-secondary ml-2">{String(s.reason || '')}</span>
                    </div>
                    <div className="text-right text-[10px] text-soc-muted">
                      Owner: {String(s.owner || 'system')} | Expires:{' '}
                      {String(s.expires_at || 'NEVER')}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Metrics breakdown */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <Metric
          label="Execution Time"
          value={formatDuration(scan.duration_seconds)}
          subtext={formatDate(scan.started_at)}
        />
        <Metric
          label="Dependencies Found"
          value={scan.components_found}
          subtext="Scanned manifests"
        />
        <Metric
          label="Matches Correlated"
          value={scan.vulnerabilities_found}
          subtext="Advisories evaluated"
        />
        <Metric
          label="KEV Exploits"
          value={scan.kev_matches}
          subtext="Known in wild"
          variant={scan.kev_matches > 0 ? 'critical' : 'default'}
        />
        <Metric
          label="Requires Review"
          value={scan.summary?.requires_review ?? 0}
          subtext="Discrepancies / AI flag"
          variant={(scan.summary?.requires_review ?? 0) > 0 ? 'warning' : 'default'}
        />
      </div>

      {/* Matches List */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-soc-primary">
            Correlated Vulnerability Matches
          </h2>
          <span className="text-xs font-mono text-soc-muted">
            Click any row to open Deep Intelligence & Audit Trace
          </span>
        </div>

        <DataTable
          columns={matchColumns}
          data={matches}
          keyExtractor={(m) => m.id}
          isLoading={false}
          emptyTitle="No vulnerability matches detected"
          emptyDescription="None of the detected project dependencies matched known vulnerability version ranges."
          onRowClick={(m) => navigate(`/matches/${m.id}`)}
        />
      </div>
    </div>
  );
};

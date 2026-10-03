import React from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { RotateCw, Layers, Database, ShieldAlert, ExternalLink, GitFork } from 'lucide-react';
import { PageHeader } from '@/components/layout/PageHeader';
import { ApplicabilityBadge } from '@/components/badges/ApplicabilityBadge';
import { RiskBadge } from '@/components/badges/RiskBadge';
import { ReviewBadge } from '@/components/badges/ReviewBadge';
import { ConflictPanel } from '@/components/intelligence/ConflictPanel';
import { AuditTrace } from '@/components/intelligence/AuditTrace';
import { AIAnalysisCard } from '@/components/intelligence/AIAnalysisCard';
import { SystemOneCard } from '@/components/intelligence/SystemOneCard';
import { ErrorState } from '@/components/ui/ErrorState';
import { LoadingState } from '@/components/ui/LoadingState';
import { useToast } from '@/hooks/useToast';
import { matchesApi } from '@/services/api/matches';
import { formatDate, formatPercent } from '@/lib/utils';

export const MatchDetailPage: React.FC = () => {
  const { matchId } = useParams<{ matchId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { showToast } = useToast();

  const {
    data: match,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery({
    queryKey: ['match', matchId],
    queryFn: () => matchesApi.get(matchId!),
    enabled: Boolean(matchId),
  });

  const reanalyzeMutation = useMutation({
    mutationFn: () => matchesApi.reanalyze(matchId!),
    onSuccess: (updatedMatch) => {
      queryClient.setQueryData(['match', matchId], updatedMatch);
      queryClient.invalidateQueries({ queryKey: ['matches'] });
      showToast('success', 'Match re-analyzed', 'AI and Risk evaluations refreshed successfully.');
    },
    onError: (err: { message: string }) => {
      showToast('error', 'Reanalysis failed', err.message);
    },
  });

  if (isLoading) {
    return (
      <LoadingState message="Aggregating multi-source intelligence, AI evaluations, and audit traces..." />
    );
  }

  if (isError || !match) {
    return (
      <ErrorState
        title="Vulnerability Match Not Found"
        description="The requested correlation record could not be retrieved from the engine."
        requestId={(error as { requestId?: string })?.requestId}
        onRetry={() => refetch()}
      />
    );
  }

  const comp = match.component;
  const vuln = match.vulnerability;
  const requiresReview =
    match.applicability === 'REQUIRES_REVIEW' ||
    Boolean(match.risk_assessment?.requires_human_review);

  return (
    <div className="space-y-6" data-testid="match-detail-page">
      <PageHeader
        title={`Match: ${comp?.name || 'Package'} ${comp?.version || ''}`}
        subtitle={`Vulnerability Correlation: ${vuln?.cve_id || match.vulnerability_id}`}
        backTo="/matches"
        actions={
          <button
            onClick={() => reanalyzeMutation.mutate()}
            disabled={reanalyzeMutation.isPending}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-blue-600 rounded-md hover:bg-blue-500 transition-colors shadow-sm disabled:opacity-50"
            aria-label="Reanalyze match with AI engine"
          >
            <RotateCw
              className={reanalyzeMutation.isPending ? 'w-3.5 h-3.5 animate-spin' : 'w-3.5 h-3.5'}
            />
            <span>{reanalyzeMutation.isPending ? 'Reanalyzing...' : 'Re-Evaluate Match'}</span>
          </button>
        }
      />

      {/* 1. MATCH OVERVIEW */}
      <section
        aria-label="Match Overview"
        className="p-5 rounded-lg border border-soc-border bg-soc-surface space-y-4"
        data-testid="match-overview-section"
      >
        <div className="flex items-center justify-between pb-3 border-b border-soc-border">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-blue-400" />
            <h2 className="text-sm font-semibold text-soc-primary">Match Telemetry Overview</h2>
          </div>
          <span className="text-[11px] font-mono text-soc-muted">
            Correlated at {formatDate(match.matched_at)}
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          <div className="p-3 rounded bg-soc-elevated border border-soc-border">
            <span className="text-[10px] font-mono uppercase text-soc-secondary block">
              Component
            </span>
            <span className="font-mono text-xs font-bold text-soc-primary mt-1 block truncate">
              {comp?.name || '—'}
            </span>
          </div>

          <div className="p-3 rounded bg-soc-elevated border border-soc-border">
            <span className="text-[10px] font-mono uppercase text-soc-secondary block">
              Installed Version
            </span>
            <span className="font-mono text-xs font-bold text-blue-400 mt-1 block truncate">
              {comp?.version || '—'}
            </span>
          </div>

          <div className="p-3 rounded bg-soc-elevated border border-soc-border">
            <span className="text-[10px] font-mono uppercase text-soc-secondary block">
              Ecosystem
            </span>
            <span className="font-mono text-xs font-bold text-soc-primary mt-1 block uppercase truncate">
              {comp?.ecosystem || '—'}
            </span>
          </div>

          <div className="p-3 rounded bg-soc-elevated border border-soc-border">
            <span className="text-[10px] font-mono uppercase text-soc-secondary block">
              Applicability
            </span>
            <div className="mt-1">
              <ApplicabilityBadge status={match.applicability} />
            </div>
          </div>

          <div className="p-3 rounded bg-soc-elevated border border-soc-border">
            <span className="text-[10px] font-mono uppercase text-soc-secondary block">
              Risk Posture
            </span>
            <div className="mt-1">
              <RiskBadge level={match.risk_assessment?.risk_level || 'UNKNOWN'} />
            </div>
          </div>

          <div className="p-3 rounded bg-soc-elevated border border-soc-border">
            <span className="text-[10px] font-mono uppercase text-soc-secondary block">
              Human Review
            </span>
            <div className="mt-1">
              <ReviewBadge requiresReview={requiresReview} />
            </div>
          </div>
        </div>

        {/* Vulnerability advisory reference link */}
        {vuln && (
          <div className="p-3.5 rounded bg-soc-elevated/40 border border-soc-border flex items-center justify-between">
            <div>
              <span className="font-mono text-xs font-bold text-rose-400 block">{vuln.cve_id}</span>
              <p className="text-xs text-soc-secondary mt-0.5 font-sans line-clamp-1">
                {vuln.vulnerability_name || vuln.short_description || 'Security Advisory Record'}
              </p>
            </div>
            <button
              onClick={() => navigate(`/vulnerabilities/${vuln.id}`)}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-mono text-blue-400 hover:text-white rounded bg-soc-elevated border border-soc-border transition-colors"
            >
              <span>Advisory Detail</span>
              <ExternalLink className="w-3 h-3" />
            </button>
          </div>
        )}
      </section>

      {/* DEPENDENCY INTELLIGENCE & GRAPH PROVENANCE */}
      <section
        aria-label="Dependency Intelligence"
        className="p-5 rounded-lg border border-soc-border bg-soc-surface space-y-4"
        data-testid="dependency-intelligence-section"
      >
        <div className="flex items-center justify-between pb-3 border-b border-soc-border">
          <div className="flex items-center gap-2">
            <GitFork className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-semibold text-soc-primary">
              Dependency Intelligence & Graph Provenance
            </h2>
          </div>
          <span
            className={`font-mono text-[10px] font-bold px-2 py-0.5 rounded border ${
              (comp?.is_direct ?? comp?.dependency_type === 'direct')
                ? 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30'
                : 'text-purple-400 bg-purple-500/10 border-purple-500/30'
            }`}
          >
            {(comp?.is_direct ?? comp?.dependency_type === 'direct')
              ? 'DIRECT DEPENDENCY'
              : 'TRANSITIVE DEPENDENCY'}
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          <div className="p-3 rounded bg-soc-elevated border border-soc-border">
            <span className="text-[10px] font-mono uppercase text-soc-secondary block">
              Origin Source
            </span>
            <span
              className="font-mono text-xs font-semibold text-soc-primary mt-1 block truncate"
              title={comp?.lockfile_source || comp?.source_file || '—'}
            >
              {(comp?.lockfile_source || comp?.source_file || '—').split('/').pop()}
            </span>
          </div>

          <div className="p-3 rounded bg-soc-elevated border border-soc-border">
            <span className="text-[10px] font-mono uppercase text-soc-secondary block">Scope</span>
            <span className="font-mono text-xs font-semibold text-soc-secondary mt-1 uppercase block">
              {comp?.scope || 'runtime'}
            </span>
          </div>

          <div className="p-3 rounded bg-soc-elevated border border-soc-border">
            <span className="text-[10px] font-mono uppercase text-soc-secondary block">
              Manifest Source
            </span>
            <span
              className="font-mono text-xs text-soc-muted mt-1 block truncate"
              title={comp?.manifest_source || '—'}
            >
              {comp?.manifest_source
                ? comp.manifest_source.split('/').pop()
                : 'Direct from lockfile'}
            </span>
          </div>

          <div className="p-3 rounded bg-soc-elevated border border-soc-border">
            <span className="text-[10px] font-mono uppercase text-soc-secondary block">
              Immediate Parent
            </span>
            <span className="font-mono text-xs font-semibold text-soc-primary mt-1 block truncate">
              {comp?.parent_name || (comp?.is_direct ? 'Root Project' : 'Direct')}
            </span>
          </div>
        </div>

        {/* Dependency Path Chain */}
        {comp?.dependency_path && comp.dependency_path.length > 0 && (
          <div className="p-3.5 rounded bg-soc-elevated/40 border border-soc-border space-y-2">
            <span className="text-[10px] font-mono uppercase text-soc-secondary block">
              Dependency Resolution Trail
            </span>
            <div className="flex flex-wrap items-center gap-1.5 font-mono text-xs">
              <span className="text-soc-muted">project</span>
              {comp.dependency_path.map((segment, idx) => (
                <React.Fragment key={idx}>
                  <span className="text-soc-muted">→</span>
                  <span
                    className={`px-2 py-0.5 rounded border ${
                      idx === comp.dependency_path!.length - 1
                        ? 'text-rose-400 bg-rose-500/10 border-rose-500/30 font-bold'
                        : 'text-soc-primary bg-soc-elevated border-soc-border'
                    }`}
                  >
                    {segment}
                  </span>
                </React.Fragment>
              ))}
            </div>
          </div>
        )}
      </section>

      {/* 2. SOURCE CONFLICTS (Mandatory section - prominent discrepancy callout) */}
      <section aria-label="Source Conflicts Section">
        <h2 className="text-sm font-semibold text-soc-primary mb-2 flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-amber-400" />
          Multi-Source Intelligence Discrepancy & Conflicts
        </h2>
        <ConflictPanel conflicts={match.conflicts || []} />
      </section>

      {/* 3. VERSION EVIDENCE (Structured evidence breakdown per source) */}
      <section
        aria-label="Version Evidence"
        className="p-5 rounded-lg border border-soc-border bg-soc-surface space-y-3"
      >
        <div className="flex items-center justify-between pb-2 border-b border-soc-border">
          <div className="flex items-center gap-2">
            <Database className="w-4 h-4 text-blue-400" />
            <h2 className="text-sm font-semibold text-soc-primary">Source Version Evidence</h2>
          </div>
          <span className="text-[11px] font-mono text-soc-muted">
            Version-Aware Matcher Evidence Records
          </span>
        </div>

        {match.structured_evidences && match.structured_evidences.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono text-soc-secondary">
              <thead className="bg-soc-elevated/70 text-soc-primary border-b border-soc-border text-[11px] uppercase">
                <tr>
                  <th className="px-3 py-2">Source</th>
                  <th className="px-3 py-2">Identifier</th>
                  <th className="px-3 py-2">Package</th>
                  <th className="px-3 py-2">Installed</th>
                  <th className="px-3 py-2">Affected Range</th>
                  <th className="px-3 py-2">Fixed Version</th>
                  <th className="px-3 py-2">Verdict</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-soc-border">
                {match.structured_evidences.map((ev, i) => (
                  <tr key={i} className="hover:bg-soc-elevated/40">
                    <td className="px-3 py-2 font-bold text-soc-primary">{ev.source_name}</td>
                    <td className="px-3 py-2 text-rose-400">{ev.identifier}</td>
                    <td className="px-3 py-2">{ev.package_name}</td>
                    <td className="px-3 py-2 text-blue-400 font-semibold">
                      {ev.installed_version || '—'}
                    </td>
                    <td className="px-3 py-2 text-soc-primary font-bold">
                      {ev.affected_range || '—'}
                    </td>
                    <td className="px-3 py-2 text-emerald-400">{ev.fixed_version || 'None'}</td>
                    <td className="px-3 py-2">
                      <ApplicabilityBadge status={ev.status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-4 text-xs font-mono text-soc-muted bg-soc-elevated/30 rounded border border-soc-border">
            {match.evidence && match.evidence.length > 0 ? (
              <ul className="space-y-1">
                {match.evidence.map((line, idx) => (
                  <li key={idx} className="text-soc-secondary font-mono">
                    • {line}
                  </li>
                ))}
              </ul>
            ) : (
              'No discrete version evidence recorded by matcher.'
            )}
          </div>
        )}
      </section>

      {/* 4. AI ANALYSIS & SYSTEMONE CARDS (Split dual-column) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <AIAnalysisCard analysis={match.ai_analysis} />
        <SystemOneCard decision={match.decision_result} />
      </div>

      {/* 5. RISK ASSESSMENT & AUDIT TRACE */}
      <section
        aria-label="Risk Assessment & Audit Trace"
        className="p-5 rounded-lg border border-soc-border bg-soc-surface space-y-5"
      >
        <div className="flex items-center justify-between pb-3 border-b border-soc-border">
          <div>
            <h2 className="text-sm font-semibold text-soc-primary">
              Deterministic Risk Engine Assessment
            </h2>
            <p className="text-xs text-soc-secondary font-sans mt-0.5">
              Rule-based, audit-trailed certainty evaluation with zero LLM hallucination risk
            </p>
          </div>
          {match.risk_assessment && (
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-soc-muted">Certainty:</span>
              <span className="text-xs font-mono font-bold text-soc-primary">
                {formatPercent(match.risk_assessment.certainty)}
              </span>
            </div>
          )}
        </div>

        {match.risk_assessment && match.risk_assessment.recommended_action && (
          <div className="p-3.5 rounded bg-blue-950/20 border border-blue-500/30 text-xs">
            <span className="font-mono uppercase text-blue-400 font-bold block mb-1">
              Recommended Remediation Action
            </span>
            <p className="text-soc-primary font-sans leading-relaxed">
              {match.risk_assessment.recommended_action}
            </p>
          </div>
        )}

        <div>
          <h3 className="text-xs font-mono uppercase text-soc-secondary tracking-wider mb-3">
            Execution Rule Audit Trail
          </h3>
          <AuditTrace assessment={match.risk_assessment} />
        </div>
      </section>
    </div>
  );
};

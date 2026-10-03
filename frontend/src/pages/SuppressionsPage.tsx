import React, { useState, useEffect } from 'react';
import { Ban, Clock, AlertTriangle, CheckCircle2, XCircle, RefreshCw, Search } from 'lucide-react';
import { policyApi, type Suppression, type SuppressionStatus } from '@/services/api/policy';

export const SuppressionsPage: React.FC = () => {
  const [suppressions, setSuppressions] = useState<Suppression[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterStatus, setFilterStatus] = useState<SuppressionStatus | 'ALL'>('ALL');
  const [search, setSearch] = useState('');

  const fetchSuppressions = async () => {
    setLoading(true);
    try {
      const data = await policyApi.listSuppressions();
      setSuppressions(data);
    } catch {
      // Offline / demo fallback
      const now = new Date();
      const past = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      const future = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
      setSuppressions([
        {
          id: 'sup-act-001',
          project_id: null,
          match_criteria: {
            vulnerability_id: 'CVE-2023-32681',
            package_name: 'requests',
            ecosystem: 'pypi',
          },
          reason: 'Internal API proxy does not forward credentials; attack vector unreachable.',
          owner: 'lead-dev@corp.internal',
          reference: 'SEC-8891',
          expires_at: future.toISOString(),
          enabled: true,
          status: 'ACTIVE',
          created_by: 'system',
          created_at: now.toISOString(),
          updated_at: now.toISOString(),
        },
        {
          id: 'sup-exp-002',
          project_id: null,
          match_criteria: {
            vulnerability_id: 'CVE-2022-24785',
            package_name: 'moment',
            ecosystem: 'npm',
          },
          reason: 'Legacy date formatter slated for deprecation by Q3.',
          owner: 'frontend-team@corp.internal',
          reference: 'DEPR-401',
          expires_at: past.toISOString(),
          enabled: true,
          status: 'EXPIRED',
          created_by: 'system',
          created_at: past.toISOString(),
          updated_at: past.toISOString(),
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSuppressions();
  }, []);

  const filtered = suppressions.filter((s) => {
    if (filterStatus !== 'ALL' && s.status !== filterStatus) {
      return false;
    }
    const q = search.toLowerCase();
    const c = s.match_criteria || {};
    return (
      s.reason.toLowerCase().includes(q) ||
      s.owner.toLowerCase().includes(q) ||
      s.reference.toLowerCase().includes(q) ||
      (c.vulnerability_id || '').toLowerCase().includes(q) ||
      (c.package_name || '').toLowerCase().includes(q)
    );
  });

  const activeCount = suppressions.filter((s) => s.status === 'ACTIVE').length;
  const expiredCount = suppressions.filter((s) => s.status === 'EXPIRED').length;
  const disabledCount = suppressions.filter((s) => s.status === 'DISABLED').length;

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-soc-primary flex items-center gap-2">
            <Ban className="w-5 h-5 text-cyan-400" />
            Vulnerability Suppressions & Exceptions
          </h1>
          <p className="text-xs text-soc-secondary mt-1">
            Auditable security exceptions. Active suppressions exempt findings from policy failure;
            expired suppressions trigger build failures.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => fetchSuppressions()}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-soc-secondary hover:text-soc-primary bg-soc-surface border border-soc-border rounded-md hover:bg-soc-elevated transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-soc-surface border border-soc-border rounded-lg p-4 flex items-center justify-between">
          <div>
            <div className="text-[10px] uppercase font-mono text-soc-muted">Active Exceptions</div>
            <div className="text-2xl font-bold text-emerald-400 mt-1">{activeCount}</div>
            <div className="text-[10px] text-soc-secondary mt-0.5">
              Exempt from CI policy failure
            </div>
          </div>
          <CheckCircle2 className="w-8 h-8 text-emerald-500/20" />
        </div>

        <div className="bg-soc-surface border border-soc-border rounded-lg p-4 flex items-center justify-between">
          <div>
            <div className="text-[10px] uppercase font-mono text-soc-muted">
              Expired Suppressions
            </div>
            <div className="text-2xl font-bold text-amber-400 mt-1">{expiredCount}</div>
            <div className="text-[10px] text-amber-400/80 mt-0.5">
              Will fail CI scans until renewed
            </div>
          </div>
          <AlertTriangle className="w-8 h-8 text-amber-500/20" />
        </div>

        <div className="bg-soc-surface border border-soc-border rounded-lg p-4 flex items-center justify-between">
          <div>
            <div className="text-[10px] uppercase font-mono text-soc-muted">
              Disabled / Inactive
            </div>
            <div className="text-2xl font-bold text-zinc-400 mt-1">{disabledCount}</div>
            <div className="text-[10px] text-soc-secondary mt-0.5">
              Explicitly disabled by owner
            </div>
          </div>
          <XCircle className="w-8 h-8 text-zinc-500/20" />
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        {/* Status Tabs */}
        <div className="flex items-center bg-soc-surface border border-soc-border rounded-md p-0.5">
          {(['ALL', 'ACTIVE', 'EXPIRED', 'DISABLED'] as const).map((st) => (
            <button
              key={st}
              onClick={() => setFilterStatus(st)}
              className={`px-3 py-1 text-xs font-medium rounded transition-colors ${
                filterStatus === st
                  ? 'bg-soc-elevated text-soc-primary font-semibold shadow-xs'
                  : 'text-soc-muted hover:text-soc-secondary'
              }`}
            >
              {st}
            </button>
          ))}
        </div>

        {/* Search Input */}
        <div className="relative w-full sm:w-72">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-soc-muted" />
          <input
            type="text"
            placeholder="Search CVE, package, owner, reason..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 text-xs bg-soc-surface border border-soc-border rounded-md text-soc-primary focus:outline-none focus:border-blue-500"
          />
        </div>
      </div>

      {/* Suppressions Table */}
      <div className="bg-soc-surface border border-soc-border rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-soc-elevated/40 border-b border-soc-border text-soc-muted font-mono uppercase text-[10px]">
              <tr>
                <th className="py-2.5 px-4">Status</th>
                <th className="py-2.5 px-4">Target Criteria</th>
                <th className="py-2.5 px-4">Reason & Justification</th>
                <th className="py-2.5 px-4">Owner & Ref</th>
                <th className="py-2.5 px-4">Expiration</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border/60">
              {filtered.length > 0 ? (
                filtered.map((s) => {
                  const crit = s.match_criteria || {};
                  const isExpired = s.status === 'EXPIRED';
                  return (
                    <tr key={s.id} className="hover:bg-soc-elevated/20 transition-colors">
                      <td className="py-3 px-4 whitespace-nowrap">
                        <span
                          className={`inline-flex items-center gap-1 font-mono text-[10px] px-2 py-0.5 rounded border font-semibold ${
                            s.status === 'ACTIVE'
                              ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                              : s.status === 'EXPIRED'
                                ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                                : 'bg-zinc-500/10 text-zinc-400 border-zinc-500/30'
                          }`}
                        >
                          {s.status === 'ACTIVE' && <CheckCircle2 className="w-3 h-3" />}
                          {s.status === 'EXPIRED' && <AlertTriangle className="w-3 h-3" />}
                          {s.status === 'DISABLED' && <XCircle className="w-3 h-3" />}
                          {s.status}
                        </span>
                      </td>

                      <td className="py-3 px-4 font-mono">
                        <div className="font-bold text-soc-primary">
                          {crit.vulnerability_id || 'Any CVE'}
                        </div>
                        <div className="text-[11px] text-soc-secondary">
                          {crit.package_name ? (
                            <span>
                              {crit.package_name}{' '}
                              {crit.package_version ? `@ ${crit.package_version}` : ''} (
                              {crit.ecosystem || 'any'})
                            </span>
                          ) : (
                            <span className="text-soc-muted">Universal match</span>
                          )}
                        </div>
                      </td>

                      <td className="py-3 px-4 max-w-xs">
                        <p className="text-soc-primary line-clamp-2">{s.reason}</p>
                      </td>

                      <td className="py-3 px-4 whitespace-nowrap font-mono text-[11px]">
                        <div className="text-soc-primary">{s.owner}</div>
                        <div className="text-soc-muted text-[10px]">{s.reference}</div>
                      </td>

                      <td className="py-3 px-4 whitespace-nowrap font-mono text-[11px]">
                        {s.expires_at ? (
                          <div
                            className={`flex items-center gap-1 ${isExpired ? 'text-amber-400 font-bold' : 'text-soc-secondary'}`}
                          >
                            <Clock className="w-3 h-3" />
                            {new Date(s.expires_at).toLocaleDateString()}
                          </div>
                        ) : (
                          <span className="text-soc-muted">Never (Permanent)</span>
                        )}
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-soc-muted text-xs">
                    No suppressions found matching current filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

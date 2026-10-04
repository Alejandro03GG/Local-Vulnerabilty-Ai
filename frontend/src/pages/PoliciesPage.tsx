import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  FileCode2,
  RefreshCw,
  Search,
  Play,
} from 'lucide-react';
import { policyApi, type Policy, type PolicyValidateResponse } from '@/services/api/policy';
import { useI18n } from '@/i18n';

export const PoliciesPage: React.FC = () => {
  const { t } = useI18n();
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [selectedPolicy, setSelectedPolicy] = useState<Policy | null>(null);

  // Validator drawer/modal state
  const [isValidatorOpen, setIsValidatorOpen] = useState(false);
  const [yamlContent, setYamlContent] = useState<string>(`version: "1"
policy:
  name: "custom-organization-policy"
  description: "Enterprise baseline policy"
  thresholds:
    fail_on:
      - "CRITICAL"
      - "HIGH"
    fail_on_review: true
  rules:
    - id: "block-known-exploited"
      description: "Immediately fail build on active CISA KEV exploitation"
      when:
        has_kev_evidence: true
      action: "BLOCK"
      reason: "Active in-the-wild exploitation prohibited in production"
      priority: 10
    - id: "review-transitive-high"
      description: "Require human security review on transitive high vulnerabilities"
      when:
        severity: "HIGH"
        dependency_type: "TRANSITIVE"
      action: "REQUIRE_REVIEW"
      reason: "Transitive high risk requires architectural review"
      priority: 50
  default_action: "ALLOW"
`);
  const [validationResult, setValidationResult] = useState<PolicyValidateResponse | null>(null);
  const [validating, setValidating] = useState(false);

  const fetchPolicies = async () => {
    setLoading(true);
    try {
      const data = await policyApi.listPolicies();
      setPolicies(data);
      if (data.length > 0 && !selectedPolicy) {
        setSelectedPolicy(data[0]);
      }
    } catch {
      // In standalone demo or offline mode, populate sample policy
      const sample: Policy = {
        id: 'pol-default-baseline',
        name: 'default-baseline-policy',
        version: '1.0',
        description: 'Standard security baseline policy with strict CVSS & KEV enforcement',
        enabled: true,
        thresholds: {
          fail_on: ['CRITICAL'],
          fail_on_review: false,
        },
        rules: [
          {
            id: 'block-critical',
            description: 'Block critical severity findings',
            when: { severity: ['CRITICAL'] },
            action: 'BLOCK',
            reason: 'Critical severity vulnerability detected',
            priority: 10,
          },
          {
            id: 'block-cisa-kev',
            description: 'Block any actively exploited vulnerability in CISA KEV catalog',
            when: { has_kev_evidence: true },
            action: 'BLOCK',
            reason: 'Active in-the-wild exploitation confirmed',
            priority: 20,
          },
        ],
        default_action: 'ALLOW',
        metadata: { managed_by: 'security-team' },
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      setPolicies([sample]);
      setSelectedPolicy(sample);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void fetchPolicies();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- mount-time fetch
  }, []);

  const handleValidate = async () => {
    setValidating(true);
    try {
      const res = await policyApi.validatePolicy({ yaml_content: yamlContent });
      setValidationResult(res);
    } catch (err: unknown) {
      setValidationResult({
        valid: false,
        errors: [err instanceof Error ? err.message : t('policies.modal.validateFailed')],
      });
    } finally {
      setValidating(false);
    }
  };

  const filteredPolicies = policies.filter(
    (p) =>
      p.name.toLowerCase().includes(search.toLowerCase()) ||
      p.description.toLowerCase().includes(search.toLowerCase()),
  );

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-soc-primary flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-blue-400" />
            {t('policies.title')}
          </h1>
          <p className="text-xs text-soc-secondary mt-1">{t('policies.subtitle')}</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => fetchPolicies()}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-soc-secondary hover:text-soc-primary bg-soc-surface border border-soc-border rounded-md hover:bg-soc-elevated transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            {t('policies.refresh')}
          </button>
          <button
            onClick={() => setIsValidatorOpen(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-blue-600 hover:bg-blue-500 rounded-md transition-colors"
          >
            <FileCode2 className="w-3.5 h-3.5" />
            {t('policies.validateButton')}
          </button>
        </div>
      </div>

      {/* Main Content: Split Master-Detail */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Policy List */}
        <div className="lg:col-span-1 space-y-4">
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-soc-muted" />
            <input
              type="text"
              placeholder={t('policies.filterPlaceholder')}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 text-xs bg-soc-surface border border-soc-border rounded-md text-soc-primary focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="space-y-2">
            {filteredPolicies.map((pol) => {
              const isSelected = selectedPolicy?.id === pol.id;
              return (
                <div
                  key={pol.id}
                  onClick={() => setSelectedPolicy(pol)}
                  className={`p-3 rounded-lg border cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-blue-600/10 border-blue-500/50 shadow-sm'
                      : 'bg-soc-surface border-soc-border hover:bg-soc-elevated/40'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="font-semibold text-xs text-soc-primary truncate">
                      {pol.name}
                    </div>
                    <span
                      className={`text-[10px] font-mono px-1.5 py-0.5 rounded border uppercase ${
                        pol.enabled
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                          : 'bg-zinc-500/10 text-zinc-400 border-zinc-500/30'
                      }`}
                    >
                      {pol.enabled ? t('policies.enabled') : t('policies.disabled')}
                    </span>
                  </div>
                  <p className="text-[11px] text-soc-secondary line-clamp-2 mt-1">
                    {pol.description || t('policies.noDescription')}
                  </p>
                  <div className="flex items-center gap-3 mt-3 text-[10px] text-soc-muted font-mono">
                    <span>{t('policies.rulesCount', { count: pol.rules?.length || 0 })}</span>
                    <span>
                      {t('policies.failOn', {
                        levels: pol.thresholds?.fail_on?.join(', ') || t('policies.none'),
                      })}
                    </span>
                    <span>{t('policies.defaultAction', { action: pol.default_action })}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Policy Detail & Rules */}
        <div className="lg:col-span-2">
          {selectedPolicy ? (
            <div className="bg-soc-surface border border-soc-border rounded-lg p-5 space-y-6">
              {/* Header Info */}
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-soc-border pb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-base font-bold text-soc-primary">{selectedPolicy.name}</h2>
                    <span className="text-[10px] font-mono bg-soc-elevated px-2 py-0.5 rounded text-soc-secondary">
                      v{selectedPolicy.version}
                    </span>
                  </div>
                  <p className="text-xs text-soc-secondary mt-1">{selectedPolicy.description}</p>
                </div>
                <div className="text-right font-mono text-[11px] text-soc-muted">
                  {t('policies.idLabel')}{' '}
                  <span className="text-soc-secondary">{selectedPolicy.id.slice(0, 12)}...</span>
                </div>
              </div>

              {/* Thresholds Banner */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="bg-soc-elevated/40 border border-soc-border rounded-md p-3">
                  <div className="text-[10px] text-soc-muted uppercase tracking-wider font-semibold">
                    {t('policies.globalFailSeverities')}
                  </div>
                  <div className="text-xs font-mono font-medium text-soc-primary mt-1">
                    {selectedPolicy.thresholds?.fail_on?.length > 0 ? (
                      <div className="flex flex-wrap gap-1 mt-1">
                        {selectedPolicy.thresholds.fail_on.map((lvl) => (
                          <span
                            key={lvl}
                            className="bg-red-500/10 text-red-400 border border-red-500/30 px-1.5 py-0.5 rounded text-[10px]"
                          >
                            {lvl}
                          </span>
                        ))}
                      </div>
                    ) : (
                      t('policies.none')
                    )}
                  </div>
                </div>

                <div className="bg-soc-elevated/40 border border-soc-border rounded-md p-3">
                  <div className="text-[10px] text-soc-muted uppercase tracking-wider font-semibold">
                    {t('policies.failOnReview')}
                  </div>
                  <div className="text-xs font-mono font-medium text-soc-primary mt-1">
                    {selectedPolicy.thresholds?.fail_on_review ? (
                      <span className="text-amber-400 flex items-center gap-1">
                        <AlertTriangle className="w-3.5 h-3.5" /> {t('policies.enforced')}
                      </span>
                    ) : (
                      <span className="text-soc-secondary">{t('policies.disabled')}</span>
                    )}
                  </div>
                </div>

                <div className="bg-soc-elevated/40 border border-soc-border rounded-md p-3">
                  <div className="text-[10px] text-soc-muted uppercase tracking-wider font-semibold">
                    {t('policies.defaultFallback')}
                  </div>
                  <div className="text-xs font-mono font-medium text-soc-primary mt-1">
                    <span className="text-blue-400">{selectedPolicy.default_action}</span>
                  </div>
                </div>
              </div>

              {/* Rules List */}
              <div className="space-y-3">
                <h3 className="text-xs font-bold uppercase tracking-wider text-soc-secondary flex items-center justify-between">
                  <span>
                    {t('policies.evaluatedRules', { count: selectedPolicy.rules?.length || 0 })}
                  </span>
                  <span className="text-[10px] font-normal text-soc-muted">
                    {t('policies.precedence')}
                  </span>
                </h3>

                {selectedPolicy.rules && selectedPolicy.rules.length > 0 ? (
                  <div className="space-y-2">
                    {selectedPolicy.rules.map((rule, idx) => (
                      <div
                        key={rule.id || idx}
                        className="bg-soc-elevated/30 border border-soc-border rounded-md p-3 space-y-2"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <span className="text-[11px] font-mono font-bold text-blue-400">
                              {rule.id}
                            </span>
                            <span className="text-[10px] text-soc-muted font-mono">
                              {t('policies.priority', { value: rule.priority ?? 100 })}
                            </span>
                          </div>
                          <span
                            className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase border ${
                              rule.action === 'BLOCK'
                                ? 'bg-red-500/10 text-red-400 border-red-500/30'
                                : rule.action === 'REQUIRE_REVIEW'
                                  ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                                  : rule.action === 'ACCEPT_RISK'
                                    ? 'bg-purple-500/10 text-purple-400 border-purple-500/30'
                                    : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                            }`}
                          >
                            {rule.action}
                          </span>
                        </div>
                        {rule.description && (
                          <p className="text-xs text-soc-primary">{rule.description}</p>
                        )}
                        <div className="bg-soc-bg border border-soc-border/60 rounded p-2 text-[11px] font-mono text-soc-secondary">
                          <span className="text-soc-muted">{t('policies.when')}</span>
                          {JSON.stringify(rule.when)}
                        </div>
                        {rule.reason && (
                          <div className="text-[11px] text-soc-muted italic">
                            {t('policies.reason', { reason: rule.reason })}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8 text-xs text-soc-muted border border-dashed border-soc-border rounded-md">
                    {t('policies.noRules')}
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="h-full flex items-center justify-center p-12 text-center text-xs text-soc-muted border border-dashed border-soc-border rounded-lg">
              {t('policies.selectPolicy')}
            </div>
          )}
        </div>
      </div>

      {/* Validate Policy Modal */}
      {isValidatorOpen && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-soc-surface border border-soc-border rounded-lg max-w-2xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
            <div className="px-5 py-4 border-b border-soc-border flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileCode2 className="w-4 h-4 text-blue-400" />
                <h3 className="text-sm font-bold text-soc-primary">{t('policies.modal.title')}</h3>
              </div>
              <button
                onClick={() => setIsValidatorOpen(false)}
                className="text-soc-muted hover:text-soc-primary text-xs"
                aria-label={t('policies.modal.closeIcon')}
              >
                ✕
              </button>
            </div>

            <div className="p-5 overflow-y-auto space-y-4 flex-1">
              <p className="text-xs text-soc-secondary">{t('policies.modal.description')}</p>

              <div>
                <textarea
                  value={yamlContent}
                  onChange={(e) => setYamlContent(e.target.value)}
                  rows={14}
                  className="w-full font-mono text-xs bg-soc-bg border border-soc-border rounded-md p-3 text-soc-primary focus:outline-none focus:border-blue-500"
                />
              </div>

              {validationResult && (
                <div
                  className={`p-3 rounded-md border text-xs font-mono ${
                    validationResult.valid
                      ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                      : 'bg-red-500/10 border-red-500/30 text-red-400'
                  }`}
                >
                  <div className="font-bold flex items-center gap-1.5">
                    {validationResult.valid ? (
                      <>
                        <CheckCircle2 className="w-4 h-4" /> {t('policies.modal.valid')}
                      </>
                    ) : (
                      <>
                        <XCircle className="w-4 h-4" /> {t('policies.modal.errors')}
                      </>
                    )}
                  </div>
                  {validationResult.errors?.length > 0 && (
                    <ul className="list-disc list-inside mt-2 space-y-1 text-[11px]">
                      {validationResult.errors.map((err, i) => (
                        <li key={i}>{err}</li>
                      ))}
                    </ul>
                  )}
                  {validationResult.policy && (
                    <div className="mt-2 text-[11px] text-soc-secondary">
                      {t('policies.modal.parsedName')}{' '}
                      <span className="font-semibold text-soc-primary">
                        {validationResult.policy.name}
                      </span>{' '}
                      |{' '}
                      {t('policies.modal.parsedRules', {
                        count: validationResult.policy.rules?.length || 0,
                      })}
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="px-5 py-3 border-t border-soc-border flex items-center justify-end gap-2 bg-soc-elevated/20">
              <button
                onClick={() => setIsValidatorOpen(false)}
                className="px-3 py-1.5 text-xs text-soc-secondary hover:text-soc-primary bg-soc-surface border border-soc-border rounded-md"
              >
                {t('policies.modal.close')}
              </button>
              <button
                onClick={handleValidate}
                disabled={validating}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-blue-600 hover:bg-blue-500 rounded-md disabled:opacity-50"
              >
                <Play className="w-3.5 h-3.5" />
                {validating ? t('policies.modal.validating') : t('policies.modal.validate')}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

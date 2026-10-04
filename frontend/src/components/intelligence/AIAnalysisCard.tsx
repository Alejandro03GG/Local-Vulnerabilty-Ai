import React from 'react';
import { Bot, Clock, Cpu, FileText, CheckCircle2, ShieldAlert } from 'lucide-react';
import { cn, formatDuration } from '@/lib/utils';
import { useI18n } from '@/i18n';
import type { AIAnalysis } from '@/types';

interface AIAnalysisCardProps {
  analysis: AIAnalysis | null | undefined;
  className?: string;
}

export const AIAnalysisCard: React.FC<AIAnalysisCardProps> = ({ analysis, className }) => {
  const { t } = useI18n();

  if (!analysis) {
    return (
      <div
        className={cn(
          'p-6 rounded-lg border border-soc-border bg-soc-surface text-center',
          className,
        )}
      >
        <Bot className="w-8 h-8 text-soc-muted mx-auto mb-2" />
        <p className="text-sm font-medium text-soc-secondary">
          {t('intelligence.aiAnalysis.emptyTitle')}
        </p>
        <span className="text-xs text-soc-muted block mt-1">
          {t('intelligence.aiAnalysis.emptyHint')}
        </span>
      </div>
    );
  }

  return (
    <div
      className={cn(
        'rounded-lg border border-soc-border bg-soc-surface overflow-hidden',
        className,
      )}
      data-testid="ai-analysis-card"
    >
      {/* Header with clear boundary badge */}
      <div className="p-4 bg-soc-elevated/80 border-b border-soc-border flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Bot className="w-5 h-5 text-blue-400" aria-hidden="true" />
          <h3 className="text-sm font-semibold text-soc-primary">
            {t('intelligence.aiAnalysis.title')}
          </h3>
        </div>
        <span className="text-[11px] font-mono text-soc-secondary bg-blue-500/10 text-blue-300 border border-blue-500/20 px-2.5 py-0.5 rounded">
          {t('intelligence.aiAnalysis.boundary')}
        </span>
      </div>

      <div className="p-5 space-y-4">
        {/* Narrative / Explanation */}
        <div>
          <h4 className="text-xs font-mono uppercase text-soc-secondary tracking-wider mb-1.5 flex items-center gap-1.5">
            <FileText className="w-3.5 h-3.5" />
            {t('intelligence.aiAnalysis.executiveSummary')}
          </h4>
          <p className="text-sm text-soc-primary/90 leading-relaxed font-sans bg-soc-elevated/40 p-3.5 rounded border border-soc-border">
            {analysis.explanation}
          </p>
        </div>

        {/* Contextual Findings */}
        {analysis.contextual_findings && analysis.contextual_findings.length > 0 && (
          <div>
            <h4 className="text-xs font-mono uppercase text-soc-secondary tracking-wider mb-2">
              {t('intelligence.aiAnalysis.observations')}
            </h4>
            <ul className="space-y-1.5 text-xs text-soc-secondary">
              {analysis.contextual_findings.map((finding, idx) => (
                <li
                  key={idx}
                  className="flex items-start gap-2 bg-soc-elevated/30 p-2 rounded border border-soc-border/60"
                >
                  <CheckCircle2 className="w-3.5 h-3.5 text-blue-400 shrink-0 mt-0.5" />
                  <span>{finding}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Evidence Considered */}
        {analysis.evidence && analysis.evidence.length > 0 && (
          <div>
            <h4 className="text-xs font-mono uppercase text-soc-secondary tracking-wider mb-2">
              {t('intelligence.aiAnalysis.evidence')}
            </h4>
            <div className="flex flex-wrap gap-2">
              {analysis.evidence.map((item, idx) => (
                <span
                  key={idx}
                  className="text-xs font-mono bg-soc-elevated text-soc-secondary px-2.5 py-1 rounded border border-soc-border"
                >
                  {item}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Human review flag */}
        {analysis.requires_human_review && (
          <div className="flex items-center gap-2 p-2.5 rounded bg-amber-500/10 border border-amber-500/20 text-xs text-amber-300">
            <ShieldAlert className="w-4 h-4 shrink-0" />
            <span>{t('intelligence.aiAnalysis.humanReview')}</span>
          </div>
        )}

        {/* Metadata Footer */}
        <div className="pt-3 border-t border-soc-border flex flex-wrap items-center gap-4 text-xs font-mono text-soc-muted">
          <div className="flex items-center gap-1.5">
            <Cpu className="w-3.5 h-3.5" />
            <span>
              {analysis.provider} ({analysis.model})
            </span>
          </div>
          <div className="flex items-center gap-1.5">
            <Clock className="w-3.5 h-3.5" />
            <span>
              {t('intelligence.aiAnalysis.latency', {
                duration: formatDuration(analysis.duration_seconds),
              })}
            </span>
          </div>
          {analysis.tokens_used > 0 && (
            <div>
              <span>{t('intelligence.aiAnalysis.tokens', { count: analysis.tokens_used })}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

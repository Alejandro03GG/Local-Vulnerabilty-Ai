import React from 'react';
import { Network, Zap, Clock, CheckCircle } from 'lucide-react';
import { cn, formatDuration, formatPercent } from '@/lib/utils';
import type { DecisionResult } from '@/types';

interface SystemOneCardProps {
  decision: DecisionResult | null | undefined;
  className?: string;
}

export const SystemOneCard: React.FC<SystemOneCardProps> = ({ decision, className }) => {
  if (!decision) {
    return (
      <div
        className={cn(
          'p-6 rounded-lg border border-soc-border bg-soc-surface text-center',
          className,
        )}
      >
        <Network className="w-8 h-8 text-soc-muted mx-auto mb-2" />
        <p className="text-sm font-medium text-soc-secondary">No SystemOne evaluation available.</p>
        <span className="text-xs text-soc-muted block mt-1">
          Fast-inference decision support can be enabled during scans.
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
      data-testid="systemone-card"
    >
      {/* Header */}
      <div className="p-4 bg-soc-elevated/80 border-b border-soc-border flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Zap className="w-5 h-5 text-indigo-400" aria-hidden="true" />
          <h3 className="text-sm font-semibold text-soc-primary">SystemOne Decision Support</h3>
        </div>
        <span className="text-[11px] font-mono text-indigo-300 bg-indigo-500/10 border border-indigo-500/20 px-2.5 py-0.5 rounded">
          Decision support — supplementary metric
        </span>
      </div>

      <div className="p-5 space-y-4">
        {/* Core Probabilities & Urgency */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div className="p-3 rounded-lg bg-soc-elevated border border-soc-border">
            <span className="text-xs font-mono uppercase text-soc-secondary tracking-wider block">
              Applicability Probability
            </span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-2xl font-bold font-mono text-soc-primary">
                {formatPercent(decision.applicability_probability)}
              </span>
              <span className="text-xs text-soc-muted font-mono">
                ({decision.applicability_probability.toFixed(3)})
              </span>
            </div>
            <div className="w-full bg-soc-bg rounded-full h-1.5 mt-2 overflow-hidden">
              <div
                className="bg-indigo-500 h-1.5 rounded-full transition-all duration-300"
                style={{
                  width: `${Math.min(Math.max(decision.applicability_probability * 100, 0), 100)}%`,
                }}
              />
            </div>
          </div>

          <div className="p-3 rounded-lg bg-soc-elevated border border-soc-border">
            <span className="text-xs font-mono uppercase text-soc-secondary tracking-wider block">
              Urgency Score
            </span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-2xl font-bold font-mono text-soc-primary">
                {decision.urgency_score.toFixed(2)}
              </span>
              <span className="text-xs text-soc-muted font-mono">/ 10.0</span>
            </div>
            <div className="w-full bg-soc-bg rounded-full h-1.5 mt-2 overflow-hidden">
              <div
                className="bg-purple-500 h-1.5 rounded-full transition-all duration-300"
                style={{ width: `${Math.min(Math.max(decision.urgency_score * 10, 0), 100)}%` }}
              />
            </div>
          </div>
        </div>

        {/* Structured Answers */}
        {decision.responses && Object.keys(decision.responses).length > 0 && (
          <div>
            <h4 className="text-xs font-mono uppercase text-soc-secondary tracking-wider mb-2">
              Structured Evaluation Questions
            </h4>
            <div className="space-y-2">
              {Object.entries(decision.responses).map(([question, answer]) => (
                <div
                  key={question}
                  className="p-2.5 rounded bg-soc-elevated/40 border border-soc-border text-xs flex items-start gap-2.5"
                >
                  <CheckCircle className="w-4 h-4 text-indigo-400 shrink-0 mt-0.5" />
                  <div className="flex-1">
                    <span className="text-soc-muted font-mono block text-[11px] mb-0.5">
                      {question}
                    </span>
                    <span className="text-soc-primary font-medium">{answer}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Metadata Footer */}
        <div className="pt-3 border-t border-soc-border flex flex-wrap items-center gap-4 text-xs font-mono text-soc-muted">
          <span>
            Provider: {decision.provider} ({decision.model})
          </span>
          <div className="flex items-center gap-1.5">
            <Clock className="w-3.5 h-3.5" />
            <span>Inference: {formatDuration(decision.latency_seconds)}</span>
          </div>
        </div>
      </div>
    </div>
  );
};

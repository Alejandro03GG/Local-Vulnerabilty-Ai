import React from 'react';
import { LucideIcon } from 'lucide-react';
import { cn } from '@/lib/utils';

interface MetricProps {
  label: string;
  value: string | number;
  subtext?: string;
  icon?: LucideIcon;
  variant?: 'default' | 'critical' | 'high' | 'warning' | 'success' | 'info';
  className?: string;
}

export const Metric: React.FC<MetricProps> = ({
  label,
  value,
  subtext,
  icon: Icon,
  variant = 'default',
  className,
}) => {
  const getVariantStyles = () => {
    switch (variant) {
      case 'critical':
        return 'border-red-500/30 bg-red-950/10 text-red-400';
      case 'high':
        return 'border-orange-500/30 bg-orange-950/10 text-orange-400';
      case 'warning':
        return 'border-amber-500/30 bg-amber-950/10 text-amber-400';
      case 'success':
        return 'border-emerald-500/30 bg-emerald-950/10 text-emerald-400';
      case 'info':
        return 'border-blue-500/30 bg-blue-950/10 text-blue-400';
      default:
        return 'border-soc-border bg-soc-surface text-soc-primary';
    }
  };

  return (
    <div
      className={cn(
        'p-4 rounded-lg border transition-all duration-150',
        getVariantStyles(),
        className,
      )}
    >
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs font-mono font-medium text-soc-secondary tracking-wider uppercase">
          {label}
        </span>
        {Icon && <Icon className="w-4 h-4 opacity-75" aria-hidden="true" />}
      </div>
      <div className="text-2xl font-bold font-mono tracking-tight mt-1">{value}</div>
      {subtext && <div className="text-xs text-soc-secondary mt-1 font-sans">{subtext}</div>}
    </div>
  );
};

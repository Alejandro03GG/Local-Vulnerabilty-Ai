import React from 'react';
import { ArrowUpDown, ArrowUp, ArrowDown } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useI18n } from '@/i18n';
import { TableSkeleton } from './LoadingState';
import { EmptyState } from './EmptyState';

export interface Column<T> {
  key: string;
  header: string;
  render?: (item: T) => React.ReactNode;
  sortable?: boolean;
  className?: string;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  keyExtractor: (item: T) => string;
  isLoading?: boolean;
  emptyTitle?: string;
  emptyDescription?: string;
  onRowClick?: (item: T) => void;
  className?: string;
}

export function DataTable<T>({
  columns,
  data,
  keyExtractor,
  isLoading = false,
  emptyTitle,
  emptyDescription,
  onRowClick,
  className,
}: DataTableProps<T>) {
  const { t } = useI18n();
  const [sortKey, setSortKey] = React.useState<string | null>(null);
  const [sortDir, setSortDir] = React.useState<'asc' | 'desc'>('asc');

  const handleSort = (key: string) => {
    if (sortKey === key) {
      if (sortDir === 'asc') setSortDir('desc');
      else {
        setSortKey(null);
        setSortDir('asc');
      }
    } else {
      setSortKey(key);
      setSortDir('asc');
    }
  };

  const sortedData = React.useMemo(() => {
    if (!sortKey) return data;
    return [...data].sort((a, b) => {
      const aVal = (a as Record<string, unknown>)[sortKey];
      const bVal = (b as Record<string, unknown>)[sortKey];
      if (aVal === bVal) return 0;
      if (aVal === null || aVal === undefined) return 1;
      if (bVal === null || bVal === undefined) return -1;
      const res = aVal < bVal ? -1 : 1;
      return sortDir === 'asc' ? res : -res;
    });
  }, [data, sortKey, sortDir]);

  if (isLoading) {
    return <TableSkeleton rows={5} columns={columns.length} />;
  }

  if (data.length === 0) {
    return (
      <EmptyState
        title={emptyTitle ?? t('ui.dataTable.emptyTitle')}
        description={emptyDescription ?? t('ui.dataTable.emptyDescription')}
      />
    );
  }

  return (
    <div
      className={cn(
        'w-full overflow-x-auto border border-soc-border rounded-lg bg-soc-surface',
        className,
      )}
    >
      <table className="w-full text-left text-xs text-soc-secondary">
        <thead className="bg-soc-elevated/70 text-soc-primary font-mono uppercase tracking-wider border-b border-soc-border text-[11px]">
          <tr>
            {columns.map((col) => {
              const isSorted = sortKey === col.key;
              return (
                <th
                  key={col.key}
                  scope="col"
                  className={cn(
                    'px-4 py-3 font-semibold select-none',
                    col.sortable && 'cursor-pointer hover:text-white transition-colors',
                    col.className,
                  )}
                  onClick={() => col.sortable && handleSort(col.key)}
                >
                  <div className="flex items-center gap-1.5">
                    <span>{col.header}</span>
                    {col.sortable && (
                      <span className="text-soc-muted">
                        {isSorted ? (
                          sortDir === 'asc' ? (
                            <ArrowUp className="w-3.5 h-3.5 text-blue-400" />
                          ) : (
                            <ArrowDown className="w-3.5 h-3.5 text-blue-400" />
                          )
                        ) : (
                          <ArrowUpDown className="w-3 h-3 opacity-40 hover:opacity-100" />
                        )}
                      </span>
                    )}
                  </div>
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody className="divide-y divide-soc-border">
          {sortedData.map((item) => (
            <tr
              key={keyExtractor(item)}
              onClick={() => onRowClick && onRowClick(item)}
              tabIndex={onRowClick ? 0 : undefined}
              onKeyDown={(e) => {
                if (onRowClick && (e.key === 'Enter' || e.key === ' ')) {
                  e.preventDefault();
                  onRowClick(item);
                }
              }}
              className={cn(
                'transition-colors duration-150',
                onRowClick &&
                  'cursor-pointer hover:bg-soc-elevated/50 focus:outline-none focus:bg-soc-elevated/60',
              )}
            >
              {columns.map((col) => (
                <td
                  key={col.key}
                  className={cn(
                    'px-3 sm:px-4 py-3 align-middle min-w-0 max-w-[18rem]',
                    col.className,
                  )}
                >
                  <div className="min-w-0 max-w-full overflow-hidden">
                    {col.render
                      ? col.render(item)
                      : String((item as Record<string, unknown>)[col.key] ?? '—')}
                  </div>
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

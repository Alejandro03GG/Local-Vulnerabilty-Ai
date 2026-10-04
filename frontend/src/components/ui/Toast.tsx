import React, { useState, useCallback } from 'react';
import { CheckCircle2, AlertTriangle, AlertOctagon, Info, X } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useI18n } from '@/i18n';
import { ToastContext, type ToastType, type ToastItem } from '@/context/ToastContext';

export type { ToastType, ToastItem };

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { t } = useI18n();
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const removeToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((item) => item.id !== id));
  }, []);

  const showToast = useCallback(
    (type: ToastType, title: string, description?: string) => {
      const id = Math.random().toString(36).substring(2, 9);
      setToasts((prev) => [...prev, { id, type, title, description }]);
      setTimeout(() => {
        removeToast(id);
      }, 4000);
    },
    [removeToast],
  );

  return (
    <ToastContext.Provider value={{ showToast }}>
      {children}
      <div
        className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none"
        aria-live="polite"
      >
        {toasts.map((toast) => {
          const getIcon = () => {
            switch (toast.type) {
              case 'success':
                return <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />;
              case 'warning':
                return <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />;
              case 'error':
                return <AlertOctagon className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />;
              default:
                return <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />;
            }
          };

          const getBorder = () => {
            switch (toast.type) {
              case 'success':
                return 'border-emerald-500/30 bg-soc-elevated/95';
              case 'warning':
                return 'border-amber-500/30 bg-soc-elevated/95';
              case 'error':
                return 'border-rose-500/30 bg-soc-elevated/95';
              default:
                return 'border-blue-500/30 bg-soc-elevated/95';
            }
          };

          return (
            <div
              key={toast.id}
              className={cn(
                'pointer-events-auto flex items-start gap-3 p-3.5 rounded-lg border shadow-lg backdrop-blur text-sm text-soc-primary transition-all animate-in fade-in slide-in-from-bottom-2',
                getBorder(),
              )}
            >
              {getIcon()}
              <div className="flex-1">
                <div className="font-semibold text-soc-primary leading-tight">{toast.title}</div>
                {toast.description && (
                  <div className="text-xs text-soc-secondary mt-0.5 leading-snug">
                    {toast.description}
                  </div>
                )}
              </div>
              <button
                onClick={() => removeToast(toast.id)}
                className="text-soc-muted hover:text-soc-primary transition-colors p-0.5"
                aria-label={t('ui.toast.dismiss')}
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
};

import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { Plus, Play, Trash2, Folder, ExternalLink } from 'lucide-react';
import { PageHeader } from '@/components/layout/PageHeader';
import { DataTable, Column } from '@/components/ui/DataTable';
import { ErrorState } from '@/components/ui/ErrorState';
import { useToast } from '@/hooks/useToast';
import { projectsApi } from '@/services/api/projects';
import { scansApi } from '@/services/api/scans';
import { formatDate } from '@/lib/utils';
import { useI18n } from '@/i18n';
import type { Project } from '@/types';

export const ProjectsPage: React.FC = () => {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { showToast } = useToast();
  const { t, dateLocale } = useI18n();

  const [isModalOpen, setIsModalOpen] = useState(false);
  const [newName, setNewName] = useState('');
  const [newPath, setNewPath] = useState('');

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['projects'],
    queryFn: () => projectsApi.list(1, 100),
  });

  const createMutation = useMutation({
    mutationFn: projectsApi.create,
    onSuccess: (project) => {
      queryClient.invalidateQueries({ queryKey: ['projects'] });
      setIsModalOpen(false);
      setNewName('');
      setNewPath('');
      showToast(
        'success',
        t('projects.toast.created'),
        t('projects.toast.createdDescription', { name: project.name }),
      );
    },
    onError: (err: { message: string }) => {
      showToast('error', t('projects.toast.createFailed'), err.message);
    },
  });

  const scanMutation = useMutation({
    mutationFn: (projectId: string) => scansApi.runProjectScan(projectId),
    onSuccess: (scan) => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      queryClient.invalidateQueries({ queryKey: ['matches'] });
      showToast(
        'success',
        t('projects.toast.scanInitiated'),
        t('projects.toast.scanStarted', { id: scan.id.substring(0, 8) }),
      );
      navigate(`/scans/${scan.id}`);
    },
    onError: (err: { message: string }) => {
      showToast('error', t('projects.toast.scanFailed'), err.message);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: projectsApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['projects'] });
      showToast('info', t('projects.toast.deleted'), t('projects.toast.deletedDescription'));
    },
    onError: (err: { message: string }) => {
      showToast('error', t('projects.toast.deleteFailed'), err.message);
    },
  });

  const handleCreateSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newName.trim() || !newPath.trim()) return;
    createMutation.mutate({ name: newName.trim(), path: newPath.trim() });
  };

  const columns: Column<Project>[] = [
    {
      key: 'name',
      header: t('projects.cols.name'),
      sortable: true,
      render: (p) => (
        <div className="flex items-center gap-2">
          <Folder className="w-4 h-4 text-blue-400 shrink-0" />
          <span className="font-semibold text-soc-primary">{p.name}</span>
        </div>
      ),
    },
    {
      key: 'path',
      header: t('projects.cols.path'),
      render: (p) => (
        <span
          className="font-mono text-xs text-soc-secondary truncate max-w-xs block"
          title={p.path}
        >
          {p.path}
        </span>
      ),
    },
    {
      key: 'created_at',
      header: t('projects.cols.registered'),
      sortable: true,
      render: (p) => (
        <span className="font-mono text-xs">{formatDate(p.created_at, dateLocale)}</span>
      ),
    },
    {
      key: 'updated_at',
      header: t('projects.cols.updated'),
      sortable: true,
      render: (p) => (
        <span className="font-mono text-xs">{formatDate(p.updated_at, dateLocale)}</span>
      ),
    },
    {
      key: 'actions',
      header: t('projects.cols.actions'),
      className: 'text-right',
      render: (p) => (
        <div className="flex items-center justify-end gap-2" onClick={(e) => e.stopPropagation()}>
          <button
            onClick={() => scanMutation.mutate(p.id)}
            disabled={scanMutation.isPending}
            className="p-1.5 rounded bg-blue-600/10 text-blue-400 hover:bg-blue-600/20 border border-blue-500/30 transition-colors"
            title={t('projects.runScan')}
            aria-label={t('projects.ariaRunScan', { name: p.name })}
          >
            <Play className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => navigate(`/projects/${p.id}`)}
            className="p-1.5 rounded bg-soc-elevated text-soc-secondary hover:text-white border border-soc-border transition-colors"
            title={t('projects.viewDetails')}
            aria-label={t('projects.ariaViewDetails', { name: p.name })}
          >
            <ExternalLink className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => {
              if (window.confirm(t('projects.confirmDelete', { name: p.name }))) {
                deleteMutation.mutate(p.id);
              }
            }}
            className="p-1.5 rounded bg-rose-500/10 text-rose-400 hover:bg-rose-500/20 border border-rose-500/30 transition-colors"
            title={t('projects.deleteProject')}
            aria-label={t('projects.ariaDelete', { name: p.name })}
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      ),
    },
  ];

  if (isError) {
    return (
      <ErrorState
        title={t('projects.errorTitle')}
        description={t('projects.errorDescription')}
        requestId={(error as { requestId?: string })?.requestId}
        onRetry={() => refetch()}
      />
    );
  }

  return (
    <div className="space-y-6" data-testid="projects-page">
      <PageHeader
        title={t('projects.title')}
        subtitle={t('projects.subtitle')}
        actions={
          <button
            onClick={() => setIsModalOpen(true)}
            className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-semibold text-white bg-blue-600 rounded-md hover:bg-blue-500 transition-colors shadow-sm"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>{t('projects.register')}</span>
          </button>
        }
      />

      <DataTable
        columns={columns}
        data={data?.items ?? []}
        keyExtractor={(p) => p.id}
        isLoading={isLoading}
        emptyTitle={t('projects.emptyTitle')}
        emptyDescription={t('projects.emptyDescription')}
        onRowClick={(p) => navigate(`/projects/${p.id}`)}
      />

      {/* Register Project Modal */}
      {isModalOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
          role="dialog"
          aria-modal="true"
        >
          <div className="w-full max-w-md p-6 bg-soc-surface border border-soc-border rounded-xl shadow-2xl">
            <h3 className="text-base font-semibold text-soc-primary mb-1">
              {t('projects.modal.title')}
            </h3>
            <p className="text-xs text-soc-secondary mb-4">{t('projects.modal.description')}</p>

            <form onSubmit={handleCreateSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-mono uppercase text-soc-secondary mb-1">
                  {t('projects.modal.nameLabel')}
                </label>
                <input
                  type="text"
                  required
                  placeholder={t('projects.modal.namePlaceholder')}
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  className="w-full px-3 py-2 text-xs rounded bg-soc-elevated border border-soc-border text-soc-primary focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs font-mono uppercase text-soc-secondary mb-1">
                  {t('projects.modal.pathLabel')}
                </label>
                <input
                  type="text"
                  required
                  placeholder={t('projects.modal.pathPlaceholder')}
                  value={newPath}
                  onChange={(e) => setNewPath(e.target.value)}
                  className="w-full px-3 py-2 text-xs font-mono rounded bg-soc-elevated border border-soc-border text-soc-primary focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="flex justify-end gap-2.5 pt-3 border-t border-soc-border">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-3 py-2 text-xs rounded bg-soc-elevated border border-soc-border text-soc-secondary hover:text-white transition-colors"
                >
                  {t('projects.modal.cancel')}
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isPending}
                  className="px-4 py-2 text-xs font-semibold text-white bg-blue-600 rounded hover:bg-blue-500 transition-colors disabled:opacity-50"
                >
                  {createMutation.isPending ? t('projects.modal.saving') : t('projects.modal.add')}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

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
import type { Project } from '@/types';

export const ProjectsPage: React.FC = () => {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { showToast } = useToast();

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
      showToast('success', 'Project created', `Project "${project.name}" added successfully.`);
    },
    onError: (err: { message: string }) => {
      showToast('error', 'Failed to create project', err.message);
    },
  });

  const scanMutation = useMutation({
    mutationFn: (projectId: string) => scansApi.runProjectScan(projectId),
    onSuccess: (scan) => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      queryClient.invalidateQueries({ queryKey: ['matches'] });
      showToast('success', 'Scan initiated', `Scan ${scan.id.substring(0, 8)} started.`);
      navigate(`/scans/${scan.id}`);
    },
    onError: (err: { message: string }) => {
      showToast('error', 'Scan failed to start', err.message);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: projectsApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['projects'] });
      showToast('info', 'Project deleted', 'Project removed from local registry.');
    },
    onError: (err: { message: string }) => {
      showToast('error', 'Failed to delete project', err.message);
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
      header: 'Project Name',
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
      header: 'Directory Path',
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
      header: 'Registered',
      sortable: true,
      render: (p) => <span className="font-mono text-xs">{formatDate(p.created_at)}</span>,
    },
    {
      key: 'updated_at',
      header: 'Last Updated',
      sortable: true,
      render: (p) => <span className="font-mono text-xs">{formatDate(p.updated_at)}</span>,
    },
    {
      key: 'actions',
      header: 'Actions',
      className: 'text-right',
      render: (p) => (
        <div className="flex items-center justify-end gap-2" onClick={(e) => e.stopPropagation()}>
          <button
            onClick={() => scanMutation.mutate(p.id)}
            disabled={scanMutation.isPending}
            className="p-1.5 rounded bg-blue-600/10 text-blue-400 hover:bg-blue-600/20 border border-blue-500/30 transition-colors"
            title="Run Security Scan"
            aria-label={`Run scan on ${p.name}`}
          >
            <Play className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => navigate(`/projects/${p.id}`)}
            className="p-1.5 rounded bg-soc-elevated text-soc-secondary hover:text-white border border-soc-border transition-colors"
            title="View Details"
            aria-label={`View details of ${p.name}`}
          >
            <ExternalLink className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => {
              if (window.confirm(`Are you sure you want to delete project "${p.name}"?`)) {
                deleteMutation.mutate(p.id);
              }
            }}
            className="p-1.5 rounded bg-rose-500/10 text-rose-400 hover:bg-rose-500/20 border border-rose-500/30 transition-colors"
            title="Delete Project"
            aria-label={`Delete ${p.name}`}
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
        title="Failed to Load Projects"
        description="Could not query projects from backend repository."
        requestId={(error as { requestId?: string })?.requestId}
        onRetry={() => refetch()}
      />
    );
  }

  return (
    <div className="space-y-6" data-testid="projects-page">
      <PageHeader
        title="Configured Projects"
        subtitle="Manage target repositories and local codebases evaluated by the vulnerability engine"
        actions={
          <button
            onClick={() => setIsModalOpen(true)}
            className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-semibold text-white bg-blue-600 rounded-md hover:bg-blue-500 transition-colors shadow-sm"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Register Project</span>
          </button>
        }
      />

      <DataTable
        columns={columns}
        data={data?.items ?? []}
        keyExtractor={(p) => p.id}
        isLoading={isLoading}
        emptyTitle="No projects configured"
        emptyDescription="Add a project path to scan Python requirements, poetry, or pipfile dependencies."
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
            <h3 className="text-base font-semibold text-soc-primary mb-1">Register New Project</h3>
            <p className="text-xs text-soc-secondary mb-4">
              Enter the project name and absolute directory path accessible by the local backend.
            </p>

            <form onSubmit={handleCreateSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-mono uppercase text-soc-secondary mb-1">
                  Project Name
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. My Web App"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  className="w-full px-3 py-2 text-xs rounded bg-soc-elevated border border-soc-border text-soc-primary focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs font-mono uppercase text-soc-secondary mb-1">
                  Absolute Directory Path
                </label>
                <input
                  type="text"
                  required
                  placeholder="/Users/.../my-repo"
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
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isPending}
                  className="px-4 py-2 text-xs font-semibold text-white bg-blue-600 rounded hover:bg-blue-500 transition-colors disabled:opacity-50"
                >
                  {createMutation.isPending ? 'Saving...' : 'Add Project'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

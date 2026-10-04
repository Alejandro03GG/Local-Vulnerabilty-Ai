import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ToastProvider } from '@/components/ui/Toast';
import { LanguageProvider } from '@/i18n';
import { ContainerImagesPage } from '@/pages/ContainerImagesPage';
import { ImageDetailPage } from '@/pages/ImageDetailPage';
import * as imagesApiModule from '@/services/api/images';
import type { ContainerImage, ContainerLayer, ContainerComponent } from '@/types';
import { mockConflictedMatch } from './fixtures';

const mockContainerImage: ContainerImage = {
  id: 'img-test-123',
  scan_id: 'scan-container-123',
  reference: 'docker.io/library/alpine:3.18',
  digest: 'sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234',
  architecture: 'amd64',
  os: 'linux',
  os_family: 'alpine',
  os_version: '3.18.4',
  os_codename: 'alpine',
  source_type: 'docker_archive',
  source_path: '/tmp/alpine.tar',
  created_at: '2026-10-02T12:00:00Z',
  layer_count: 1,
  layers: [],
};

const mockLayers: ContainerLayer[] = [
  {
    id: 'layer-1',
    layer_index: 0,
    digest: 'sha256:layerdigest11111111111111111111111111111111111111111111111111111111',
    size_bytes: 3500000,
    media_type: 'application/vnd.docker.image.rootfs.diff.tar',
    command: 'ADD alpine-minirootfs-3.18.4-x86_64.tar.gz /',
  },
];

const mockComponents: ContainerComponent[] = [
  {
    id: 'comp-os-1',
    name: 'apk-tools',
    version: '2.14.0-r2',
    ecosystem: 'alpine',
    component_type: 'os_package',
    layer_digest: 'sha256:layerdigest11111111111111111111111111111111111111111111111111111111',
    container_path: '/lib/apk/db/installed',
    package_manager: 'apk',
    is_direct: true,
  },
  {
    id: 'comp-app-1',
    name: 'urllib3',
    version: '2.31.0',
    ecosystem: 'PyPI',
    component_type: 'direct',
    layer_digest: 'sha256:layerdigest11111111111111111111111111111111111111111111111111111111',
    container_path: '/app/requirements.txt',
    package_manager: 'pip',
    is_direct: true,
  },
];

describe('Container Scanning Pages (Etapa 17)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const renderWithProviders = (
    initialRoute: string,
    element: React.ReactNode,
    path = initialRoute,
  ) => {
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    return render(
      <LanguageProvider>
        <QueryClientProvider client={queryClient}>
          <ToastProvider>
            <MemoryRouter initialEntries={[initialRoute]}>
              <Routes>
                <Route path={path} element={element} />
              </Routes>
            </MemoryRouter>
          </ToastProvider>
        </QueryClientProvider>
      </LanguageProvider>,
    );
  };

  it('renders ContainerImagesPage with image list and metrics', async () => {
    vi.spyOn(imagesApiModule.imagesApi, 'list').mockResolvedValue({
      items: [mockContainerImage],
      page: 1,
      page_size: 50,
      total: 1,
    });

    renderWithProviders('/images', <ContainerImagesPage />);

    expect(await screen.findByText('Container Images & Dockerfiles')).toBeInTheDocument();
    expect(await screen.findByText('docker.io/library/alpine:3.18')).toBeInTheDocument();
    expect(screen.getByText('linux (3.18.4)')).toBeInTheDocument();
    expect(screen.getByText(/docker_archive/i)).toBeInTheDocument();
  });

  it('opens Scan Image Archive modal and submits scan', async () => {
    vi.spyOn(imagesApiModule.imagesApi, 'list').mockResolvedValue({
      items: [],
      page: 1,
      page_size: 50,
      total: 0,
    });
    const scanSpy = vi
      .spyOn(imagesApiModule.imagesApi, 'scanImage')
      .mockResolvedValue(mockContainerImage);

    renderWithProviders('/images', <ContainerImagesPage />);

    // Click "Scan Image Archive" button
    const openBtn = await screen.findByRole('button', { name: /Scan Image Archive/i });
    fireEvent.click(openBtn);

    expect(screen.getByText('Scan Container Archive')).toBeInTheDocument();

    // Fill form with exact placeholder
    const pathInput = screen.getByPlaceholderText('/path/to/image.tar');
    fireEvent.change(pathInput, { target: { value: '/tmp/test-image.tar' } });

    // Submit
    const submitBtn = screen.getByRole('button', { name: /Start Static Scan/i });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(scanSpy).toHaveBeenCalledWith({
        archive_path: '/tmp/test-image.tar',
        reference: undefined,
        no_ai: false,
      });
    });
  });

  it('opens Dockerfile Scanner modal and parses content statically', async () => {
    vi.spyOn(imagesApiModule.imagesApi, 'list').mockResolvedValue({
      items: [],
      page: 1,
      page_size: 50,
      total: 0,
    });
    const dockerfileSpy = vi.spyOn(imagesApiModule.imagesApi, 'scanDockerfile').mockResolvedValue({
      source_file: 'Dockerfile',
      stages: [
        { index: 0, name: 'builder', base_image: 'golang:1.21-alpine', is_runtime: false },
        { index: 1, name: 'runtime', base_image: 'alpine:3.18', is_runtime: true },
      ],
      base_images: [
        { repository: 'golang', tag: '1.21-alpine', line_number: 1 },
        { repository: 'alpine', tag: '3.18', line_number: 5 },
      ],
      package_installations: [{ manager: 'apk', packages: 'ca-certificates tzdata', line: 6 }],
      copied_files: [],
      dependency_manifests: ['requirements.txt'],
    });

    renderWithProviders('/images', <ContainerImagesPage />);

    const openBtn = await screen.findByRole('button', { name: /Analyze Dockerfile/i });
    fireEvent.click(openBtn);

    expect(screen.getByText('Static Dockerfile AST Analysis')).toBeInTheDocument();

    const textarea = screen.getByPlaceholderText(/FROM alpine/i);
    fireEvent.change(textarea, {
      target: { value: 'FROM alpine:3.18\nRUN apk add --no-cache tzdata' },
    });

    const analyzeBtn = screen.getByRole('button', { name: /Parse & Analyze/i });
    fireEvent.click(analyzeBtn);

    await waitFor(() => {
      expect(dockerfileSpy).toHaveBeenCalledWith({
        content: 'FROM alpine:3.18\nRUN apk add --no-cache tzdata',
        path: undefined,
      });
    });

    // Verify AST results rendered
    expect(await screen.findByText('ca-certificates tzdata')).toBeInTheDocument();
  });

  it('renders ImageDetailPage tabs and switching works properly', async () => {
    vi.spyOn(imagesApiModule.imagesApi, 'get').mockResolvedValue(mockContainerImage);
    vi.spyOn(imagesApiModule.imagesApi, 'getLayers').mockResolvedValue(mockLayers);
    vi.spyOn(imagesApiModule.imagesApi, 'getComponents').mockResolvedValue(mockComponents);
    vi.spyOn(imagesApiModule.imagesApi, 'getVulnerabilities').mockResolvedValue([
      mockConflictedMatch,
    ]);
    vi.spyOn(imagesApiModule.imagesApi, 'getDependencyGraph').mockResolvedValue({
      image_id: 'img-test-123',
      scan_id: 'scan-container-123',
      nodes: [
        { id: 'c1', label: 'apk-tools@2.14.0-r2', type: 'os_package', depth: 0 },
        { id: 'c2', label: 'urllib3@2.31.0', type: 'direct', depth: 0 },
      ],
      edges: [],
    });
    vi.spyOn(imagesApiModule.imagesApi, 'getPolicy').mockResolvedValue({
      policy_id: 'pol-1',
      policy_name: 'Default Security Policy',
      status: 'ALLOWED',
      total_findings: 1,
      allowed_count: 1,
      violations_count: 0,
      suppressed_count: 0,
      accepted_risk_count: 0,
      requires_review_count: 0,
      has_violations: false,
      ci_exit_code: 0,
      evaluations: [],
      violations: [],
      suppressions_applied: [],
      evaluated_at: '2026-10-02T12:00:00Z',
    });

    renderWithProviders('/images/img-test-123', <ImageDetailPage />, '/images/:imageId');

    // Overview tab default
    expect(
      await screen.findByRole('heading', { level: 1, name: /alpine:3\.18/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        /Static container inspection • Architecture: amd64 • Format: DOCKER_ARCHIVE/i,
      ),
    ).toBeInTheDocument();

    // Click Layers tab
    fireEvent.click(screen.getByRole('button', { name: /Layers/i }));
    expect(await screen.findByText(/ADD alpine-minirootfs/i)).toBeInTheDocument();

    // Click Components tab
    fireEvent.click(screen.getByRole('button', { name: /Components/i }));
    expect(await screen.findByText('apk-tools')).toBeInTheDocument();
    expect(screen.getByText('urllib3')).toBeInTheDocument();

    // Filter to OS Packages
    fireEvent.click(screen.getByRole('button', { name: /OS Packages/i }));
    expect(screen.getByText('apk-tools')).toBeInTheDocument();
    expect(screen.queryByText('urllib3')).not.toBeInTheDocument();

    // Filter to Application Packages
    fireEvent.click(screen.getByRole('button', { name: /Application Dependencies/i }));
    expect(screen.getByText('urllib3')).toBeInTheDocument();
    expect(screen.queryByText('apk-tools')).not.toBeInTheDocument();

    // Click Findings tab
    fireEvent.click(screen.getByRole('button', { name: /Findings/i }));
    expect(await screen.findByText('CVE-2024-37891')).toBeInTheDocument();

    // Click Dependency Graph tab
    fireEvent.click(screen.getByRole('button', { name: /Dependency Graph/i }));
    expect(await screen.findByText('Container Dependency Topology')).toBeInTheDocument();
  });
});

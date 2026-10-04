import { screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { render } from './renderWithLanguage';
import { DataTable } from '@/components/ui/DataTable';
import { Metric } from '@/components/ui/Metric';
import { Shield } from 'lucide-react';

describe('DataTable & Metric UI Components', () => {
  const sampleData = [
    { id: '1', name: 'requests', version: '2.28.1' },
    { id: '2', name: 'fastapi', version: '0.110.0' },
  ];

  const columns = [
    { key: 'name', header: 'Package', sortable: true },
    { key: 'version', header: 'Version' },
  ];

  it('renders table headers and rows correctly', () => {
    render(<DataTable columns={columns} data={sampleData} keyExtractor={(item) => item.id} />);

    expect(screen.getByText('Package')).toBeInTheDocument();
    expect(screen.getByText('Version')).toBeInTheDocument();
    expect(screen.getByText('requests')).toBeInTheDocument();
    expect(screen.getByText('fastapi')).toBeInTheDocument();
  });

  it('handles row click callback', () => {
    const onRowClick = vi.fn();
    render(
      <DataTable
        columns={columns}
        data={sampleData}
        keyExtractor={(item) => item.id}
        onRowClick={onRowClick}
      />,
    );

    fireEvent.click(screen.getByText('requests'));
    expect(onRowClick).toHaveBeenCalledWith(sampleData[0]);
  });

  it('renders Metric component with label, value, and icon', () => {
    render(
      <Metric
        label="Critical Risks"
        value={5}
        subtext="Immediate remediation"
        icon={Shield}
        variant="critical"
      />,
    );

    expect(screen.getByText('Critical Risks')).toBeInTheDocument();
    expect(screen.getByText('5')).toBeInTheDocument();
    expect(screen.getByText('Immediate remediation')).toBeInTheDocument();
  });
});

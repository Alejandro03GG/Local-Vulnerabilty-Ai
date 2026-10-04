import { screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { render } from './renderWithLanguage';
import { ConflictPanel } from '@/components/intelligence/ConflictPanel';
import { AuditTrace } from '@/components/intelligence/AuditTrace';
import { mockConflict, mockRiskAssessmentWithConflict } from './fixtures';

describe('ConflictPanel & AuditTrace', () => {
  it('displays empty state when no conflicts exist', () => {
    render(<ConflictPanel conflicts={[]} />);
    expect(screen.getByTestId('no-source-conflicts')).toBeInTheDocument();
    expect(screen.getByText('No source conflicts detected.')).toBeInTheDocument();
  });

  it('displays multi-source conflict breakdown when discrepancies exist', () => {
    render(<ConflictPanel conflicts={[mockConflict]} />);

    expect(screen.getByTestId('source-conflict-panel')).toBeInTheDocument();
    expect(screen.getByText('SOURCE APPLICABILITY CONFLICT')).toBeInTheDocument();
    expect(screen.getByText('OSV')).toBeInTheDocument();
    expect(screen.getByText('NVD')).toBeInTheDocument();
    expect(screen.getByText('LIKELY_AFFECTED')).toBeInTheDocument();
    expect(screen.getByText('LIKELY_NOT_AFFECTED')).toBeInTheDocument();
    expect(screen.getByText('REQUIRES_REVIEW')).toBeInTheDocument();
    expect(screen.getByText(/OSV indicates affected range/)).toBeInTheDocument();
  });

  it('renders timeline rules in AuditTrace component', () => {
    render(<AuditTrace assessment={mockRiskAssessmentWithConflict} />);

    expect(screen.getByTestId('audit-trace')).toBeInTheDocument();
    expect(screen.getByText('Source Applicability Conflict Detected')).toBeInTheDocument();
    expect(
      screen.getByText('CISA Known Exploited Vulnerabilities (KEV) Confirmed'),
    ).toBeInTheDocument();
    expect(screen.getByText('Concrete Version Declared')).toBeInTheDocument();
    expect(screen.getByText(/Conflict between sources requires human/)).toBeInTheDocument();
  });
});

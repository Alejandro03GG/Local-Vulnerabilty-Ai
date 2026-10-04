import { screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { render } from './renderWithLanguage';
import { ApplicabilityBadge } from '@/components/badges/ApplicabilityBadge';
import { RiskBadge } from '@/components/badges/RiskBadge';
import { ScanStatusBadge } from '@/components/badges/ScanStatusBadge';
import { SourceStatusBadge } from '@/components/badges/SourceStatusBadge';
import { ReviewBadge } from '@/components/badges/ReviewBadge';

describe('Semantic Badges', () => {
  it('renders all required applicability badges correctly', () => {
    const statuses = [
      'LIKELY_AFFECTED',
      'LIKELY_NOT_AFFECTED',
      'REQUIRES_REVIEW',
      'DETECTED',
      'UNKNOWN',
    ] as const;

    for (const status of statuses) {
      const { unmount } = render(<ApplicabilityBadge status={status} />);
      expect(screen.getByText(status)).toBeInTheDocument();
      // Ensure VULNERABLE is never used
      expect(screen.queryByText(/VULNERABLE/i)).not.toBeInTheDocument();
      unmount();
    }
  });

  it('renders all risk levels correctly', () => {
    const levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;

    for (const level of levels) {
      const { unmount } = render(<RiskBadge level={level} />);
      expect(screen.getByText(level)).toBeInTheDocument();
      unmount();
    }
  });

  it('renders scan status badges correctly', () => {
    const statuses = ['running', 'pending', 'completed', 'failed'] as const;
    for (const status of statuses) {
      const { unmount } = render(<ScanStatusBadge status={status} />);
      expect(screen.getByText(status.toUpperCase())).toBeInTheDocument();
      unmount();
    }
  });

  it('renders source status badge', () => {
    const { rerender } = render(<SourceStatusBadge isAvailable={true} />);
    expect(screen.getByText('AVAILABLE')).toBeInTheDocument();

    rerender(<SourceStatusBadge isAvailable={false} />);
    expect(screen.getByText('UNAVAILABLE')).toBeInTheDocument();
  });

  it('renders human review badge', () => {
    const { rerender } = render(<ReviewBadge requiresReview={true} />);
    expect(screen.getByText('HUMAN REVIEW REQUIRED')).toBeInTheDocument();

    rerender(<ReviewBadge requiresReview={false} />);
    expect(screen.getByText('NO REVIEW NEEDED')).toBeInTheDocument();
  });
});

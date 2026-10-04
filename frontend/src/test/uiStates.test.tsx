import { screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { render } from './renderWithLanguage';
import { LoadingState } from '@/components/ui/LoadingState';
import { ErrorState } from '@/components/ui/ErrorState';
import { EmptyState } from '@/components/ui/EmptyState';

describe('UI Feedback States', () => {
  it('renders LoadingState with message and skeleton rows', () => {
    render(<LoadingState message="Scanning environment..." rows={3} />);
    expect(screen.getByTestId('loading-state')).toBeInTheDocument();
    expect(screen.getByText('Scanning environment...')).toBeInTheDocument();
  });

  it('renders EmptyState with action trigger', () => {
    const onAction = vi.fn();
    render(
      <EmptyState
        title="No Scans Found"
        description="Launch your first scan"
        action={{ label: 'Start Scan', onClick: onAction }}
      />,
    );

    expect(screen.getByTestId('empty-state')).toBeInTheDocument();
    expect(screen.getByText('No Scans Found')).toBeInTheDocument();

    const button = screen.getByText('Start Scan');
    fireEvent.click(button);
    expect(onAction).toHaveBeenCalledTimes(1);
  });

  it('renders ErrorState with request ID and retry trigger', () => {
    const onRetry = vi.fn();
    render(
      <ErrorState
        title="Gateway Unreachable"
        description="Check local port 8000"
        requestId="req-xyz-999"
        onRetry={onRetry}
      />,
    );

    expect(screen.getByTestId('error-state')).toBeInTheDocument();
    expect(screen.getByText('Gateway Unreachable')).toBeInTheDocument();
    expect(screen.getByText('req-xyz-999')).toBeInTheDocument();

    const retryBtn = screen.getByText('Retry Operation');
    fireEvent.click(retryBtn);
    expect(onRetry).toHaveBeenCalledTimes(1);
  });
});

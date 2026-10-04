import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MatchDetailPage } from '@/pages/MatchDetailPage';
import { ToastProvider } from '@/components/ui/Toast';
import { LanguageProvider } from '@/i18n';
import { mockConflictedMatch } from './fixtures';
import * as matchesApiModule from '@/services/api/matches';

describe('CRITICAL REQUIREMENT — Match with source conflict (Etapa 10 §55)', () => {
  it('renders REQUIRES_REVIEW, SOURCE_APPLICABILITY_CONFLICT, and human review, but NEVER renders VULNERABLE', async () => {
    vi.spyOn(matchesApiModule.matchesApi, 'get').mockResolvedValue(mockConflictedMatch);

    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });

    const { container } = render(
      <LanguageProvider>
        <QueryClientProvider client={queryClient}>
          <ToastProvider>
            <MemoryRouter initialEntries={['/matches/match-conflict-001']}>
              <Routes>
                <Route path="/matches/:matchId" element={<MatchDetailPage />} />
              </Routes>
            </MemoryRouter>
          </ToastProvider>
        </QueryClientProvider>
      </LanguageProvider>,
    );

    // 1. Wait for match data to load into the DOM
    expect(await screen.findByText('SOURCE APPLICABILITY CONFLICT')).toBeInTheDocument();

    // 2. Check for REQUIRES_REVIEW status
    const reviewBadges = screen.getAllByText('REQUIRES_REVIEW');
    expect(reviewBadges.length).toBeGreaterThan(0);

    // 3. Check for human review indicator
    expect(screen.getByText('HUMAN REVIEW REQUIRED')).toBeInTheDocument();

    // 4. Verify component and advisory names
    expect(screen.getAllByText('urllib3').length).toBeGreaterThan(0);
    expect(screen.getAllByText('CVE-2024-37891').length).toBeGreaterThan(0);

    // 5. CRITICAL TEST CHECK: Verify that the forbidden string "VULNERABLE" is NOT present anywhere in the DOM text
    // Note: Words like "Vulnerability" are allowed, but the exact status "VULNERABLE" must never appear!
    const pageHtml = container.innerHTML;
    // Regex looking for the word "VULNERABLE" with word boundaries to ensure it's not part of "Vulnerability"
    const hasVulnerableStatus = /\bVULNERABLE\b/i.test(pageHtml);
    expect(hasVulnerableStatus).toBe(false);
  });
});

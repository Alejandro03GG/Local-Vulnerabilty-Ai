import { describe, it, expect, vi, beforeEach } from 'vitest';
import { apiClient, ApiError } from '@/services/api/client';

describe('API Client', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('sends JSON headers and X-Request-ID', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'x-request-id': 'test-request-id-123' }),
      json: async () => ({ success: true }),
    });
    global.fetch = mockFetch;

    const data = await apiClient<{ success: boolean }>('/api/v1/health');

    expect(data).toEqual({ success: true });
    expect(mockFetch).toHaveBeenCalledTimes(1);

    const callArgs = mockFetch.mock.calls[0];
    const url = callArgs[0];
    const options = callArgs[1];

    expect(url).toContain('/api/v1/health');
    expect(options.headers['Content-Type']).toBe('application/json');
    expect(options.headers['Accept']).toBe('application/json');
    expect(options.headers['X-Request-ID']).toBeDefined();
  });

  it('throws structured ApiError on non-2xx response with backend error payload', async () => {
    const errorPayload = {
      error: {
        code: 'PROJECT_NOT_FOUND',
        message: "Project with ID 'abc' not found",
        request_id: 'req-error-789',
      },
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      statusText: 'Not Found',
      headers: new Headers({ 'x-request-id': 'req-error-789' }),
      json: async () => errorPayload,
    });

    await expect(apiClient('/api/v1/projects/abc')).rejects.toThrowError(ApiError);

    try {
      await apiClient('/api/v1/projects/abc');
    } catch (err) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(404);
      expect(apiErr.code).toBe('PROJECT_NOT_FOUND');
      expect(apiErr.message).toBe("Project with ID 'abc' not found");
      expect(apiErr.requestId).toBe('req-error-789');
    }
  });
});

export interface ApiErrorDetail {
  code?: string;
  message: string;
  details?: Record<string, unknown>;
  request_id?: string;
}

export class ApiError extends Error {
  public status: number;
  public code?: string;
  public requestId?: string;
  public details?: Record<string, unknown>;

  constructor(
    status: number,
    message: string,
    code?: string,
    requestId?: string,
    details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.requestId = requestId;
    this.details = details;
  }
}

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

function generateRequestId(): string {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  return 'req-' + Math.random().toString(36).substring(2, 11) + '-' + Date.now();
}

interface RequestOptions extends RequestInit {
  timeoutMs?: number;
}

export async function apiClient<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
  const { timeoutMs = 30000, headers = {}, ...customConfig } = options;

  const requestId = generateRequestId();
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  const url = `${BASE_URL.replace(/\/$/, '')}${endpoint.startsWith('/') ? '' : '/'}${endpoint}`;

  const requestHeaders: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
    'X-Request-ID': requestId,
    ...(headers as Record<string, string>),
  };

  try {
    const response = await fetch(url, {
      ...customConfig,
      headers: requestHeaders,
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    const resRequestId = response.headers.get('x-request-id') || requestId;

    if (!response.ok) {
      let errorData: ApiErrorDetail = {
        message: `HTTP Error ${response.status}: ${response.statusText}`,
      };
      try {
        const json = await response.json();
        if (json.error) {
          errorData = {
            code: json.error.code,
            message: json.error.message || errorData.message,
            details: json.error.details,
            request_id: json.error.request_id || resRequestId,
          };
        } else if (json.detail) {
          errorData = {
            message: typeof json.detail === 'string' ? json.detail : JSON.stringify(json.detail),
            request_id: resRequestId,
          };
        }
      } catch {
        // Non-JSON error payload
      }

      throw new ApiError(
        response.status,
        errorData.message,
        errorData.code,
        errorData.request_id || resRequestId,
        errorData.details,
      );
    }

    if (response.status === 204) {
      return {} as T;
    }

    return (await response.json()) as T;
  } catch (error) {
    clearTimeout(timeoutId);
    if (error instanceof ApiError) {
      throw error;
    }
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw new ApiError(408, 'Request timed out after ' + timeoutMs + 'ms', 'TIMEOUT', requestId);
    }
    throw new ApiError(
      0,
      error instanceof Error ? error.message : 'Network error occurred connecting to API',
      'NETWORK_ERROR',
      requestId,
    );
  }
}

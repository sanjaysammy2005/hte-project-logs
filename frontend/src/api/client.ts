/** Minimal typed client for the TraceLock API (docs/API_SPEC.md). */

const TOKEN_KEY = "tracelock.token";

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details: unknown = {},
  ) {
    super(message);
  }
}

// sessionStorage: survives a page refresh, cleared when the tab closes. Access can throw
// (private mode, blocked storage), so every use is guarded.
export function getToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string | null): void {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable: the session simply won't survive a refresh */
  }
}

let unauthorizedHandler: (() => void) | null = null;
export function onUnauthorized(handler: (() => void) | null): void {
  unauthorizedHandler = handler;
}

type Options = { method?: string; body?: unknown; params?: Record<string, string | number | undefined> };

export async function api<T>(path: string, { method = "GET", body, params }: Options = {}): Promise<T> {
  const query = params
    ? "?" +
      new URLSearchParams(
        Object.entries(params)
          .filter(([, v]) => v !== undefined && v !== "")
          .map(([k, v]) => [k, String(v)]),
      ).toString()
    : "";
  const token = getToken();
  const response = await fetch(`/api/v1${path}${query}`, {
    method,
    headers: {
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (response.status === 204) return undefined as T;
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    const error = data?.error ?? {};
    if (response.status === 401 && path !== "/auth/login") unauthorizedHandler?.();
    throw new ApiError(response.status, error.code ?? "HTTP_ERROR", error.message ?? response.statusText, error.details);
  }
  return data as T;
}

export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return `${error.message} (${error.code})`;
  return error instanceof Error ? error.message : String(error);
}

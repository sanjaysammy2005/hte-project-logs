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

function authHeader(): Record<string, string> {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

function toApiError(status: number, statusText: string, data: unknown): ApiError {
  const error = (data as { error?: { code?: string; message?: string; details?: unknown } } | null)?.error ?? {};
  if (status === 401) unauthorizedHandler?.();
  return new ApiError(status, error.code ?? "HTTP_ERROR", error.message ?? statusText, error.details);
}

/** Multipart upload with progress reporting (fetch cannot report upload progress; XHR can). */
export function upload<T>(path: string, form: FormData, onProgress?: (fraction: number) => void): Promise<T> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `/api/v1${path}`);
    for (const [k, v] of Object.entries(authHeader())) xhr.setRequestHeader(k, v);
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) onProgress?.(e.loaded / e.total);
    };
    xhr.onload = () => {
      let data: unknown = null;
      try {
        data = JSON.parse(xhr.responseText);
      } catch {
        data = null;
      }
      if (xhr.status >= 200 && xhr.status < 300) resolve(data as T);
      else reject(toApiError(xhr.status, xhr.statusText, data));
    };
    xhr.onerror = () => reject(new ApiError(0, "NETWORK_ERROR", "The upload could not reach the server"));
    xhr.send(form);
  });
}

/** Fetch file content with the bearer token in a header (never in the URL) as a Blob. */
export async function fetchBlob(path: string): Promise<{ blob: Blob; auditIndex: string | null }> {
  const response = await fetch(`/api/v1${path}`, { headers: authHeader() });
  if (!response.ok) {
    const data = await response.json().catch(() => null);
    throw toApiError(response.status, response.statusText, data);
  }
  return { blob: await response.blob(), auditIndex: response.headers.get("X-TraceLock-Audit-Index") };
}

export function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return `${error.message} (${error.code})`;
  return error instanceof Error ? error.message : String(error);
}

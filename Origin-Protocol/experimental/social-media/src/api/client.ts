const API_BASE_RAW = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.trim();
const BASE = (API_BASE_RAW && API_BASE_RAW.length > 0
  ? API_BASE_RAW
  : (import.meta.env.DEV ? '/api' : 'https://originapp.fly.dev/api')).replace(/\/+$/, '');
const API_ORIGIN = BASE.replace(/\/api$/, '');
const ABIGAIL_BASE_RAW = (import.meta.env.VITE_ABIGAIL_BASE_URL as string | undefined)?.trim();
const ABIGAIL_DEFAULT_BASE = 'https://abigail-service.fly.dev';
const ABIGAIL_BASE = (ABIGAIL_BASE_RAW && ABIGAIL_BASE_RAW.length > 0
  ? ABIGAIL_BASE_RAW
  : ABIGAIL_DEFAULT_BASE).replace(/\/+$/, '');
const ABIGAIL_API_KEY = (import.meta.env.VITE_ABIGAIL_API_KEY as string | undefined)?.trim() || '';
const ABIGAIL_TENANT_ID = (import.meta.env.VITE_ABIGAIL_TENANT_ID as string | undefined)?.trim() || '';
const ABIGAIL_LOG_KEY = 'origin_abigail_debug_logs_v1';
const ABIGAIL_SESSION_KEY_PREFIX = 'origin_abigail_session_v1_';
const ABIGAIL_RUNTIME_KEY_STORAGE = 'origin_abigail_api_key_v1';
const RATE_LIMIT_BACKOFF_MS = 45_000;
const rateLimitUntilByPath = new Map<string, number>();

function getRateLimitKey(path: string): string {
  const queryIndex = path.indexOf('?');
  return queryIndex >= 0 ? path.slice(0, queryIndex) : path;
}

function getStoredAbigailApiKey(): string {
  if (typeof window === 'undefined') return '';
  return window.localStorage.getItem(ABIGAIL_RUNTIME_KEY_STORAGE)?.trim() || '';
}

function getAbigailApiKey(): string {
  return ABIGAIL_API_KEY || getStoredAbigailApiKey();
}

export function hasAbigailApiKeyConfigured(): boolean {
  return Boolean(getAbigailApiKey());
}

export function setAbigailApiKeyRuntime(value: string): void {
  if (typeof window === 'undefined') return;
  const trimmed = value.trim();
  if (trimmed) {
    window.localStorage.setItem(ABIGAIL_RUNTIME_KEY_STORAGE, trimmed);
  } else {
    window.localStorage.removeItem(ABIGAIL_RUNTIME_KEY_STORAGE);
  }
}

if (import.meta.env.DEV) {
  console.info('[Origin API Config]', {
    baseApiUrl: BASE,
    abigailBaseUrl: ABIGAIL_BASE,
    hasAbigailApiKey: Boolean(ABIGAIL_API_KEY),
    abigailTenantId: ABIGAIL_TENANT_ID || 'public',
  });
}

export type UploadStage = 'preparing' | 'signing' | 'uploading' | 'finalizing' | 'done';
export type UploadProgress = {
  stage: UploadStage;
  percent: number;
  message: string;
};

export function resolveApiAssetUrl(url: string | null | undefined): string {
  if (!url) return '';
  if (/^https?:\/\//i.test(url)) return url;
  if (url.startsWith('/')) return `${API_ORIGIN}${url}`;
  return `${API_ORIGIN}/${url}`;
}

export function resolveApiUrl(url: string): string {
  if (/^https?:\/\//i.test(url)) return url;
  if (url.startsWith('/')) return `${API_ORIGIN}${url}`;
  return `${BASE}/${url.replace(/^\/+/, '')}`;
}

function getToken(): string | null {
  return localStorage.getItem('origin_token');
}

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => {
    window.setTimeout(resolve, ms);
  });
}

function logAbigailInteraction(entry: {
  method: string;
  path: string;
  ok: boolean;
  status?: number;
  attempt: number;
  durationMs: number;
  message: string;
  userId?: string;
}) {
  try {
    const nextEntry = {
      ...entry,
      createdAt: new Date().toISOString(),
    };
    const raw = window.localStorage.getItem(ABIGAIL_LOG_KEY);
    const existing = raw ? (JSON.parse(raw) as Array<typeof nextEntry>) : [];
    const merged = [nextEntry, ...existing].slice(0, 200);
    window.localStorage.setItem(ABIGAIL_LOG_KEY, JSON.stringify(merged));
    const level = entry.ok ? 'log' : 'warn';
    console[level]('[Abigail]', nextEntry);
  } catch {
    // ignore local debug log failures
  }
}

export function getAbigailDebugLogs(): Array<{
  method: string;
  path: string;
  ok: boolean;
  status?: number;
  attempt: number;
  durationMs: number;
  message: string;
  userId?: string;
  createdAt: string;
}> {
  try {
    const raw = window.localStorage.getItem(ABIGAIL_LOG_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

export function getOrCreateAbigailSessionId(userId: string): string {
  const key = `${ABIGAIL_SESSION_KEY_PREFIX}${userId}`;
  const existing = window.localStorage.getItem(key);
  if (existing) return existing;
  const created = `${userId}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  window.localStorage.setItem(key, created);
  return created;
}

function headers(extra: Record<string, string> = {}): Record<string, string> {
  const h: Record<string, string> = { 'Content-Type': 'application/json', ...extra };
  const t = getToken();
  if (t) h['Authorization'] = `Bearer ${t}`;
  return h;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const rateLimitKey = getRateLimitKey(path);
  const now = Date.now();
  const blockedUntil = rateLimitUntilByPath.get(rateLimitKey) ?? 0;
  if (blockedUntil > now) {
    const retryAfterSeconds = Math.ceil((blockedUntil - now) / 1000);
    throw new Error(`Rate limited on ${rateLimitKey}. Retrying in ~${retryAfterSeconds}s.`);
  }

  let res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: { ...headers(), ...(init.headers as Record<string, string> | undefined) },
  });

  // Backward compatibility for older backend deployments that still expose /messages/* instead of /messaging/*.
  if (res.status === 404 && path.startsWith('/messaging/')) {
    const legacyPath = path.replace('/messaging/', '/messages/');
    res = await fetch(`${BASE}${legacyPath}`, {
      ...init,
      headers: { ...headers(), ...(init.headers as Record<string, string> | undefined) },
    });
  }

  if (!res.ok) {
    if (res.status === 429) {
      const retryAfterHeader = Number(res.headers.get('retry-after'));
      const backoffMs = Number.isFinite(retryAfterHeader) && retryAfterHeader > 0
        ? retryAfterHeader * 1000
        : RATE_LIMIT_BACKOFF_MS;
      rateLimitUntilByPath.set(rateLimitKey, Date.now() + backoffMs);
    }
    const body = await res.json().catch(() => ({}));
    throw new Error((body as { error?: string }).error ?? `HTTP ${res.status}`);
  }

  rateLimitUntilByPath.delete(rateLimitKey);

  if (res.status === 204) {
    return undefined as T;
  }

  const text = await res.text();
  if (!text) {
    return undefined as T;
  }

  return JSON.parse(text) as T;
}

async function requestAbigail<T>(params: {
  path: string;
  method: 'GET' | 'POST';
  userId: string;
  sessionId?: string;
  query?: Record<string, string>;
  body?: Record<string, unknown>;
  retries?: number;
}): Promise<{ data: T; status: number }> {
  if (!ABIGAIL_BASE) {
    throw new Error('Abigail service URL is not configured.');
  }

  class AbigailRequestError extends Error {
    status?: number;

    isNetworkFailure: boolean;

    isServerFailure: boolean;

    isOfflineCandidate: boolean;

    constructor(message: string, options?: { status?: number; isNetworkFailure?: boolean; isServerFailure?: boolean }) {
      super(message);
      this.name = 'AbigailRequestError';
      this.status = options?.status;
      this.isNetworkFailure = Boolean(options?.isNetworkFailure);
      this.isServerFailure = Boolean(options?.isServerFailure);
      this.isOfflineCandidate = this.isNetworkFailure || this.isServerFailure;
    }
  }

  const normalizedPath = params.path.startsWith('/') ? params.path : `/${params.path}`;
  const canonicalPath = normalizedPath.startsWith('/abigail/')
    ? normalizedPath.replace(/^\/abigail/, '')
    : normalizedPath;
  const aliasPath = canonicalPath.startsWith('/abigail/') ? canonicalPath : `/abigail${canonicalPath}`;
  const candidatePaths = [...new Set([normalizedPath, canonicalPath, aliasPath])];
  const protectedCanonicalPaths = new Set(['/chat', '/memory/ingest', '/memory/update', '/memory/context', '/memory/forget', '/memory/export']);
  const isProtectedRoute = protectedCanonicalPaths.has(canonicalPath);
  const apiKey = getAbigailApiKey();

  if (isProtectedRoute && !apiKey) {
    throw new AbigailRequestError('Abigail API key is required for this route. Set VITE_ABIGAIL_API_KEY.', {
      status: 401,
    });
  }

  const maxAttempts = Math.max(1, (params.retries ?? 2) + 1);
  let lastError: Error | null = null;
  const queryString = params.query ? `?${new URLSearchParams(params.query).toString()}` : '';

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    let shouldRetry = false;

    for (let routeIndex = 0; routeIndex < candidatePaths.length; routeIndex += 1) {
      const routePath = candidatePaths[routeIndex];
      const url = `${ABIGAIL_BASE}${routePath}${queryString}`;
      const startedAt = Date.now();
      let res: Response;

      try {
        res = await fetch(url, {
          method: params.method,
          headers: {
            'Content-Type': 'application/json',
            ...(ABIGAIL_TENANT_ID ? { 'x-tenant-id': ABIGAIL_TENANT_ID } : {}),
            ...(apiKey ? { 'x-api-key': apiKey } : {}),
          },
          body: params.body ? JSON.stringify(params.body) : undefined,
        });
      } catch (err) {
        const networkError = new AbigailRequestError((err as Error)?.message || 'Network error', {
          isNetworkFailure: true,
        });
        lastError = networkError;
        const durationMs = Date.now() - startedAt;
        logAbigailInteraction({
          method: params.method,
          path: routePath,
          ok: false,
          attempt,
          durationMs,
          message: networkError.message,
          userId: params.userId,
        });

        shouldRetry = true;
        break;
      }

      const durationMs = Date.now() - startedAt;
      if (!res.ok) {
        if (res.status === 404 && routeIndex < candidatePaths.length - 1) {
          logAbigailInteraction({
            method: params.method,
            path: routePath,
            ok: false,
            status: res.status,
            attempt,
            durationMs,
            message: 'route not found, trying compatibility route',
            userId: params.userId,
          });
          continue;
        }

        const body = await res.json().catch(() => ({}));
        const rawError = (body as { detail?: string; error?: string; message?: string }).detail
          ?? (body as { detail?: string; error?: string; message?: string }).error
          ?? (body as { detail?: string; error?: string; message?: string }).message
          ?? `HTTP ${res.status}`;

        const mappedMessage = [401, 403, 422].includes(res.status)
          ? `Abigail config/contract error (HTTP ${res.status}): ${rawError}`
          : rawError;

        const requestError = new AbigailRequestError(mappedMessage, {
          status: res.status,
          isServerFailure: res.status >= 500,
        });
        lastError = requestError;

        logAbigailInteraction({
          method: params.method,
          path: routePath,
          ok: false,
          status: res.status,
          attempt,
          durationMs,
          message: mappedMessage,
          userId: params.userId,
        });

        const isRetriableStatus = res.status === 429 || res.status >= 500;
        if (isRetriableStatus) {
          shouldRetry = true;
          break;
        }

        throw requestError;
      }

      const text = await res.text();
      const parsed = text ? (JSON.parse(text) as T) : (undefined as T);
      logAbigailInteraction({
        method: params.method,
        path: routePath,
        ok: true,
        status: res.status,
        attempt,
        durationMs,
        message: 'ok',
        userId: params.userId,
      });
      return { data: parsed, status: res.status };
    }

    if (!shouldRetry || attempt >= maxAttempts) {
      break;
    }

    await wait(200 * attempt);
  }

  throw lastError ?? new Error('Abigail request failed');
}

function getAbigailErrorStatus(error: unknown): number | null {
  if (!error || typeof error !== 'object') return null;
  const maybeStatus = (error as { status?: unknown }).status;
  return typeof maybeStatus === 'number' ? maybeStatus : null;
}

export function getAbigailErrorStatusCode(error: unknown): number | null {
  return getAbigailErrorStatus(error);
}

export function isAbigailOfflineFailure(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false;
  const fromFlag = (error as { isOfflineCandidate?: unknown }).isOfflineCandidate;
  if (typeof fromFlag === 'boolean') return fromFlag;
  const status = getAbigailErrorStatus(error);
  return status !== null ? status >= 500 : true;
}

function uploadWithXhr<T>(
  url: string,
  options: {
    method?: 'POST' | 'PUT';
    body: FormData;
    token?: string | null;
    onProgress?: (fraction: number) => void;
    parseJson?: boolean;
  }
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open(options.method ?? 'POST', url, true);

    if (options.token) {
      xhr.setRequestHeader('Authorization', `Bearer ${options.token}`);
    }

    xhr.upload.onprogress = (event) => {
      if (!options.onProgress || !event.lengthComputable) return;
      const fraction = event.total > 0 ? event.loaded / event.total : 0;
      options.onProgress(Math.max(0, Math.min(1, fraction)));
    };

    xhr.onerror = () => {
      reject(new Error('Upload failed. Please check your network and try again.'));
    };

    xhr.onload = () => {
      if (xhr.status < 200 || xhr.status >= 300) {
        const body = xhr.responseText || '';
        reject(new Error(body || `HTTP ${xhr.status}`));
        return;
      }

      if (options.parseJson === false) {
        resolve(undefined as T);
        return;
      }

      try {
        const parsed = xhr.responseText ? (JSON.parse(xhr.responseText) as T) : ({} as T);
        resolve(parsed);
      } catch {
        reject(new Error('Upload succeeded, but response could not be parsed.'));
      }
    };

    xhr.send(options.body);
  });
}

// Auth
export const authApi = {
  register: (body: {
    username: string;
    email: string;
    password: string;
    displayName?: string;
    acceptTerms: true;
    subscribeToProtection?: boolean;
  }) =>
    request<{ user: import('../types').User; token: string; onboarding?: { subscribeToProtection?: boolean } }>('/auth/register', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  login: (body: { email: string; password: string }) =>
    request<{ user: import('../types').User; token: string }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
};

// Feed
export const feedApi = {
  get: (page = 1, pageSize = 20, feedType: 'home' | 'community' | 'spotlight' | 'fairness' = 'home') =>
    request<import('../types').PaginatedResponse<import('../types').VideoMeta>>(
      `/feed?page=${page}&pageSize=${pageSize}&feedType=${feedType}`
    ),
};

// Live
export const liveApi = {
  getEligibility: () =>
    request<import('../types').LiveEligibility>('/live/eligibility'),

  listSessions: (status: 'live' | 'ended' | 'all' = 'live', limit = 60) =>
    request<{ items: import('../types').LiveSession[] }>(`/live/sessions?status=${status}&limit=${Math.max(1, limit)}`),

  createSession: (body: { title: string; description?: string }) =>
    request<{ session: import('../types').LiveSession }>('/live/sessions', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  getSession: (id: string) =>
    request<{ session: import('../types').LiveSession }>(`/live/sessions/${id}`),

  endSession: (id: string) =>
    request<{ session: import('../types').LiveSession | null }>(`/live/sessions/${id}/action`, {
      method: 'POST',
      body: JSON.stringify({ action: 'end' }),
    }),

  joinSession: (id: string) =>
    request<{ session: import('../types').LiveSession | null }>(`/live/sessions/${id}/action`, {
      method: 'POST',
      body: JSON.stringify({ action: 'join' }),
    }),

  leaveSession: (id: string) =>
    request<{ session: import('../types').LiveSession | null }>(`/live/sessions/${id}/action`, {
      method: 'POST',
      body: JSON.stringify({ action: 'leave' }),
    }),

  toggleSessionLike: (id: string) =>
    request<{ liked: boolean; likeCount: number }>(`/live/sessions/${id}/like`, {
      method: 'POST',
      body: JSON.stringify({}),
    }),

  listComments: (sessionId: string) =>
    request<{ comments: import('../types').LiveComment[] }>(`/live/sessions/${sessionId}/comments`),

  postComment: (sessionId: string, body: { text: string; parentId?: string }) =>
    request<{ comment: import('../types').LiveComment }>(`/live/sessions/${sessionId}/comments`, {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  toggleCommentLike: (commentId: string) =>
    request<{ liked: boolean; likeCount: number }>(`/live/comments/${commentId}/like`, {
      method: 'POST',
      body: JSON.stringify({}),
    }),
};

// Videos
export const videosApi = {
  get: (id: string) =>
    request<{ video: import('../types').VideoMeta }>(`/videos/${id}`),

  getMeta: (id: string) =>
    request<{ video: import('../types').VideoMeta }>(`/videos/${id}/meta`),

  createCloudflareDirectUpload: (title: string) =>
    request<{ uid: string; uploadURL: string; playbackBase: string }>('/videos/cloudflare/direct-upload', {
      method: 'POST',
      body: JSON.stringify({ title }),
    }),

  finalizeCloudflareUpload: (body: {
    uid: string;
    title: string;
    description?: string;
    originBundleId?: string;
    assetId?: string;
    keyId?: string;
    contentHash?: string;
    originId?: string;
    protectedUpload?: boolean;
    protectionOptions?: string[];
    intendedPlatforms?: string[];
    originPolicy?: string;
    governanceLedgerCid?: string;
  }) =>
    request<{ video: import('../types').VideoMeta }>('/videos/cloudflare/finalize', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  publishSealed: (body: {
    creatorId?: string;
    title: string;
    description?: string;
    videoUrl: string;
    originBundleId?: string;
    assetId?: string;
    keyId?: string;
    contentHash?: string;
    originId?: string;
    originPolicy?: string;
    governanceLedgerCid?: string;
  }) =>
    request<{ video: import('../types').VideoMeta; sync?: string }>('/videos/sync/sealed', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  upload: (formData: FormData, onProgress?: (progress: UploadProgress) => void) => {
    const token = getToken();
    onProgress?.({ stage: 'uploading', percent: 10, message: 'Uploading video…' });
    return uploadWithXhr<{ video: import('../types').VideoMeta }>(`${BASE}/videos`, {
      method: 'POST',
      body: formData,
      token,
      onProgress: (fraction) => {
        const percent = 10 + Math.round(fraction * 85);
        onProgress?.({ stage: 'uploading', percent, message: 'Uploading video…' });
      },
      parseJson: true,
    }).then((result) => {
      onProgress?.({ stage: 'done', percent: 100, message: 'Upload complete' });
      return result;
    });
  },

  async uploadWithCloudflare(params: {
    file: File;
    title: string;
    description?: string;
    originBundleId?: string;
    assetId?: string;
    keyId?: string;
    contentHash?: string;
    originId?: string;
    protectedUpload?: boolean;
    protectionOptions?: string[];
    intendedPlatforms?: string[];
    originPolicy?: string;
    governanceLedgerCid?: string;
  }, onProgress?: (progress: UploadProgress) => void) {
    onProgress?.({ stage: 'preparing', percent: 2, message: 'Preparing upload…' });
    onProgress?.({ stage: 'signing', percent: 8, message: 'Requesting secure upload session…' });
    const direct = await videosApi.createCloudflareDirectUpload(params.title);

    const fd = new FormData();
    fd.append('file', params.file);

    await uploadWithXhr<void>(direct.uploadURL, {
      method: 'POST',
      body: fd,
      parseJson: false,
      onProgress: (fraction) => {
        const percent = 10 + Math.round(fraction * 80);
        onProgress?.({ stage: 'uploading', percent, message: 'Uploading to stream…' });
      },
    }).catch((err: Error) => {
      throw new Error(err.message || 'Cloudflare upload failed');
    });

    onProgress?.({ stage: 'finalizing', percent: 92, message: 'Finalizing publish…' });
    const result = await videosApi.finalizeCloudflareUpload({
      uid: direct.uid,
      title: params.title,
      description: params.description,
      originBundleId: params.originBundleId,
      assetId: params.assetId,
      keyId: params.keyId,
      contentHash: params.contentHash,
      originId: params.originId,
      protectedUpload: params.protectedUpload,
      protectionOptions: params.protectionOptions,
      intendedPlatforms: params.intendedPlatforms,
      originPolicy: params.originPolicy,
      governanceLedgerCid: params.governanceLedgerCid,
    });
    onProgress?.({ stage: 'done', percent: 100, message: 'Upload complete' });
    return result;
  },

  delete: (id: string) =>
    request<void>(`/videos/${id}`, { method: 'DELETE' }),

  like: (id: string) =>
    request<{ liked: boolean; likeCount: number }>(`/videos/${id}/like`, { method: 'POST' }),

  getComments: (id: string) =>
    request<{ comments: import('../types').Comment[] }>(`/videos/${id}/comments`),

  postComment: (id: string, text: string) =>
    request<{ comment: import('../types').Comment }>(`/videos/${id}/comments`, {
      method: 'POST',
      body: JSON.stringify({ text }),
    }),

  report: (id: string, body: { reason: string; notes?: string }) =>
    request<{ report: { id: string; status: 'open' | 'resolved' } }>(`/videos/${id}/report`, {
      method: 'POST',
      body: JSON.stringify(body),
    }),
};

// Users
export const usersApi = {
  search: (query: string, limit = 12) =>
    request<{ items: import('../types').User[] }>(
      `/users/search?query=${encodeURIComponent(query)}&limit=${Math.max(1, Math.min(limit, 30))}`
    ),

  getProfile: (id: string) =>
    request<{ user: import('../types').User }>(`/users/${id}`),

  getByUsername: (username: string) =>
    request<{ user: import('../types').User }>(`/users/by-username/${encodeURIComponent(username.trim().toLowerCase())}`),

  getVideos: (id: string) =>
    request<{ items: import('../types').VideoMeta[] }>(`/users/${id}/videos`),

  getProfileStats: (id: string) =>
    request<{
      stats: {
        followersCount: number;
        followingCount: number;
        totalVideos: number;
        totalViews: number;
        totalLikes: number;
        totalVerified: number;
        totalProtected: number;
      };
    }>(`/users/${id}/profile-stats`),

  getSocialGraph: (id: string, type: 'followers' | 'following', limit = 24) =>
    request<{
      type: 'followers' | 'following';
      total: number;
      items: import('../types').User[];
    }>(`/users/${id}/social-graph?type=${type}&limit=${Math.max(1, Math.min(limit, 100))}`),

  updateMe: (body: { username?: string; displayName?: string; bio?: string; avatarUrl?: string | null; creatorKeyId?: string }) =>
    request<{ user: import('../types').User }>('/users/me', {
      method: 'PATCH',
      body: JSON.stringify(body),
    }),

  changePassword: (body: { currentPassword: string; newPassword: string }) =>
    request<{ ok: true }>('/users/me/password', {
      method: 'PATCH',
      body: JSON.stringify(body),
    }),

  runProtectionSweep: (body?: { includeAlreadyProtected?: boolean }) =>
    request<{ updated: number; total: number }>('/users/me/videos/protection-sweep', {
      method: 'POST',
      body: JSON.stringify(body ?? {}),
    }),

  myPayouts: () =>
    request<{
      monthKey: string | null;
      creatorPool: number;
      totalEligibleViews: number;
      creatorEligibleViews: number;
      creatorShare: number;
      estimatedPayout: number;
      finalPayout: number;
      payoutsActive: boolean;
      reason: string;
    }>('/users/me/payouts'),

  getMySettings: () =>
    request<{ settings: import('../types').UserSettings }>('/users/me/settings'),

  updateMySettings: (patch: Partial<import('../types').UserSettings>) =>
    request<{ settings: import('../types').UserSettings }>('/users/me/settings', {
      method: 'PATCH',
      body: JSON.stringify(patch),
    }),

  revokeMySession: (sessionId: string) =>
    request<{ settings: import('../types').UserSettings }>('/users/me/settings/revoke-session', {
      method: 'POST',
      body: JSON.stringify({ sessionId }),
    }),

  exportMySettings: () =>
    request<{ settings: import('../types').UserSettings; exportedAt: string }>('/users/me/settings/export'),

  deleteMySettings: () =>
    request<void>('/users/me/settings', {
      method: 'DELETE',
    }),
};

export const syncHistoryApi = {
  listMine: () =>
    request<{ items: import('../utils/syncHistory').SyncHistoryItem[] }>('/users/me/sync-history'),

  create: (body: {
    status: 'success' | 'failed';
    title: string;
    videoUrl: string;
    videoId?: string;
    message?: string;
    payloadJson: string;
  }) =>
    request<{ items: import('../utils/syncHistory').SyncHistoryItem[] }>('/users/me/sync-history', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  clearMine: () =>
    request<void>('/users/me/sync-history', {
      method: 'DELETE',
    }),
};

export const membershipApi = {
  catalog: () =>
    request<{
      checkoutEnabled: boolean;
      creatorPlans: Array<{
        id: string;
        name: string;
        description: string;
        productId: string;
        mode: 'subscription' | 'payment';
        billingType: 'creator';
      }>;
      platformPlan: {
        id: string;
        name: string;
        description: string;
        productId: string;
        mode: 'subscription' | 'payment';
        billingType: 'platform';
      };
      defaults: {
        creatorProductId: string;
        mode: 'subscription' | 'payment';
      };
    }>('/membership/catalog'),

  status: () =>
    request<{
      active: boolean;
      creatorKeyId: string | null;
      billingProvider: 'stripe';
      checkoutEnabled: boolean;
      publishableKey?: string;
      meterId?: string | null;
      meterEventName?: string;
      isAdmin: boolean;
      user: import('../types').User;
    }>('/membership/status'),

  createCheckoutSession: (body?: { lookupKey?: string; productId?: string; mode?: 'subscription' | 'payment'; billingType?: 'creator' | 'platform' }) =>
    request<{ url?: string; sessionId?: string; checkoutBypassed?: boolean; active?: boolean; user?: import('../types').User }>(
      '/membership/create-checkout-session',
      {
        method: 'POST',
        body: JSON.stringify(body ?? {}),
      }
    ),

  createPortalSession: () =>
    request<{ url: string }>('/membership/create-portal-session', {
      method: 'POST',
      body: JSON.stringify({}),
    }),
};

type CreatorSettings = {
  id: string;
  userId: string;
  subscriptionsEnabled: boolean;
  createdAt: string;
  updatedAt: string;
};

type CreatorSubscriptionTier = {
  id: string;
  creatorId: string;
  name: string;
  description: string | null;
  priceMonthly: number;
  tierLevel: 1 | 2;
  stripePriceId: string | null;
  stripeProductId: string | null;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
};

export const creatorApi = {
  getSettings: () =>
    request<{ settings: CreatorSettings }>('/creator/settings'),

  updateSettings: (body: { subscriptionsEnabled: boolean }) =>
    request<{ success: true; settings: CreatorSettings }>('/creator/settings', {
      method: 'PUT',
      body: JSON.stringify(body),
    }),

  listMyTiers: () =>
    request<{ tiers: CreatorSubscriptionTier[] }>('/creator/tiers'),

  createTier: (body: { name: string; description?: string; priceMonthly: number; tierLevel: 1 | 2 }) =>
    request<{ success: true; tier: CreatorSubscriptionTier }>('/creator/tiers', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  updateTier: (tierId: string, body: { name?: string; description?: string; isActive?: boolean }) =>
    request<{ success: true; tier: CreatorSubscriptionTier }>(`/creator/tiers/${encodeURIComponent(tierId)}`, {
      method: 'PUT',
      body: JSON.stringify(body),
    }),

  deleteTier: (tierId: string) =>
    request<{ success: true }>(`/creator/tiers/${encodeURIComponent(tierId)}`, {
      method: 'DELETE',
    }),
};

export const messagingApi = {
  eventsUrl: () => {
    const token = getToken();
    const qs = token ? `?token=${encodeURIComponent(token)}` : '';
    return `${BASE}/messaging/events${qs}`;
  },

  listConversations: () =>
    request<{ items: import('../types').Conversation[] }>('/messaging/conversations'),

  createConversation: (body: {
    type?: 'dm' | 'group' | 'broadcast';
    participantIds?: string[];
    title?: string;
    allowReplies?: boolean;
    typingIndicatorsEnabled?: boolean;
    readReceiptsEnabled?: boolean;
    collaboratorIds?: string[];
  }) =>
    request<{ conversation: import('../types').Conversation }>('/messaging/conversations', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  subscribeToBroadcast: (conversationId: string) =>
    request<{ conversation: import('../types').Conversation }>(`/messaging/conversations/${conversationId}/subscribe`, {
      method: 'POST',
      body: JSON.stringify({}),
    }),

  unsubscribeFromBroadcast: (conversationId: string) =>
    request<{ conversation: import('../types').Conversation }>(`/messaging/conversations/${conversationId}/subscribe`, {
      method: 'DELETE',
    }),

  listMessages: (conversationId: string, cursor?: string, limit = 40) =>
    request<{ items: import('../types').ConversationMessage[]; nextCursor: string | null }>(
      `/messaging/conversations/${conversationId}/messages?limit=${Math.max(1, limit)}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`
    ),

  sendMessage: (conversationId: string, body: {
    content?: string;
    attachments?: import('../types').MessageAttachment[];
    replyToMessageId?: string;
  }) =>
    request<{ message: import('../types').ConversationMessage; conversation: import('../types').Conversation }>(
      `/messaging/conversations/${conversationId}/messages`,
      {
        method: 'POST',
        body: JSON.stringify(body),
      }
    ),

  reactToMessage: (messageId: string, emoji: string) =>
    request<{ message: import('../types').ConversationMessage }>(`/messaging/messages/${messageId}/react`, {
      method: 'POST',
      body: JSON.stringify({ emoji }),
    }),

  markConversationRead: (conversationId: string) =>
    request<{ state: import('../types').ConversationMemberState }>(`/messaging/conversations/${conversationId}/messages/read`, {
      method: 'POST',
      body: JSON.stringify({}),
    }),

  setTyping: (conversationId: string, isTyping: boolean) =>
    request<{ ok: boolean; suppressed?: boolean }>(`/messaging/conversations/${conversationId}/typing`, {
      method: 'POST',
      body: JSON.stringify({ isTyping }),
    }),

  updateConversationSettings: (
    conversationId: string,
    body: { muted?: boolean; pinned?: boolean; quietModeUntil?: string | null }
  ) =>
    request<{ state: import('../types').ConversationMemberState }>(`/messaging/conversations/${conversationId}/settings`, {
      method: 'PATCH',
      body: JSON.stringify(body),
    }),

  reportMessage: (messageId: string, reason: string) =>
    request<{ report: { id: string; reporterId: string; reportedUserId: string; messageId: string; reason: string; createdAt: string } }>(
      `/messaging/messages/${messageId}/report`,
      {
        method: 'POST',
        body: JSON.stringify({ reason }),
      }
    ),

  listNotifications: (cursor?: string, limit = 30, unreadOnly = false) =>
    request<{ items: import('../types').AppNotification[]; nextCursor: string | null; unreadCount: number }>(
      `/messaging/notifications?limit=${Math.max(1, limit)}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}${unreadOnly ? '&unreadOnly=1' : ''}`
    ),

  markNotificationRead: (id: string) =>
    request<{ notification: import('../types').AppNotification }>(`/messaging/notifications/${id}/read`, {
      method: 'POST',
      body: JSON.stringify({}),
    }),

  markAllNotificationsRead: () =>
    request<{ marked: number }>('/messaging/notifications/read-all', {
      method: 'POST',
      body: JSON.stringify({}),
    }),

  getNotificationSettings: () =>
    request<{ settings: import('../types').NotificationSettings }>('/messaging/notifications/settings'),

  updateNotificationSettings: (body: {
    categories?: Partial<Record<import('../types').NotificationCategory, import('../types').NotificationChannelPreference>>;
    quietHours?: Partial<import('../types').NotificationSettings['quietHours']>;
    experience?: Partial<import('../types').NotificationSettings['experience']>;
  }) =>
    request<{ settings: import('../types').NotificationSettings }>('/messaging/notifications/settings', {
      method: 'PATCH',
      body: JSON.stringify(body),
    }),

  getCreatorNotificationPreference: (creatorId: string) =>
    request<{ preference: import('../types').CreatorNotificationPreference }>(`/messaging/notifications/creators/${creatorId}`),

  updateCreatorNotificationPreference: (
    creatorId: string,
    body: Partial<Pick<import('../types').CreatorNotificationPreference, 'upload' | 'broadcast' | 'muted'>>
  ) =>
    request<{ preference: import('../types').CreatorNotificationPreference }>(`/messaging/notifications/creators/${creatorId}`, {
      method: 'PATCH',
      body: JSON.stringify(body),
    }),

  listBlocks: () =>
    request<{ items: Array<{ blockerId: string; blockedId: string; createdAt: string }> }>('/messaging/blocks'),

  blockUser: (blockedUserId: string) =>
    request<{ block: { blockerId: string; blockedId: string; createdAt: string } }>(`/messaging/blocks/${blockedUserId}`, {
      method: 'POST',
      body: JSON.stringify({}),
    }),

  unblockUser: (blockedUserId: string) =>
    request<{ ok: true }>(`/messaging/blocks/${blockedUserId}`, {
      method: 'DELETE',
    }),
};

export const adminApi = {
  dashboard: () =>
    request<{
      admin: { email: string };
      summary: {
        usersTotal: number;
        videosTotal: number;
        bundlesTotal: number;
        verification: {
          sealed: number;
          unsealed: number;
          verified: number;
          failed: number;
          pending: number;
          revokedOrInvalid: number;
        };
        creatorSubscriptions: number;
        bannedUsers: number;
        openReports: number;
        usageEventsTotal: number;
        errorLogsTotal: number;
        latestToolVersion: string | null;
      };
      users: Array<{
        id: string;
        username: string;
        email: string;
        displayName: string;
        creatorKeyId: string | null;
        isAdmin?: boolean;
        createdAt: string;
        banned?: boolean;
      }>;
      videos: import('../types').VideoMeta[];
      bundles: Array<{
        id: string;
        title: string;
        creatorId: string;
        originBundleId: string | null;
        originVerified: boolean;
        createdAt: string;
      }>;
      reports: Array<{
        id: string;
        videoId: string;
        reporterUserId: string;
        reason: string;
        notes?: string;
        status: 'open' | 'resolved';
        createdAt: string;
        resolvedAt?: string;
        resolvedByUserId?: string;
      }>;
      errorLogs: Array<{
        id: string;
        source: string;
        message: string;
        level: 'warning' | 'error';
        createdAt: string;
        meta?: string;
      }>;
      toolVersions: Array<{
        id: string;
        version: string;
        notes?: string;
        fileName?: string;
        isLatest: boolean;
        forceUpdate: boolean;
        downloadCount: number;
        createdAt: string;
      }>;
      usage: {
        events: Array<{ id: string; metric: string; value: number; createdAt: string; userId?: string; source?: string }>;
        byMetric: Record<string, number>;
      };
      billing: {
        provider: 'stripe';
        creatorSubscriptions: Array<{
          userId: string;
          email: string;
          displayName: string;
          creatorAccess: boolean;
          creatorKeyId: string | null;
          banned?: boolean;
          status: string;
        }>;
        meterId: string | null;
        meterEventName: string;
      };
    }>('/admin/dashboard'),

  createToolVersion: (body: { version: string; notes?: string; fileName?: string; isLatest?: boolean; forceUpdate?: boolean }) =>
    request<{ item: { id: string; version: string } }>('/admin/tool-versions', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  updateToolVersion: (id: string, body: { isLatest?: boolean; forceUpdate?: boolean }) =>
    request<{ item: { id: string; version: string; isLatest: boolean; forceUpdate: boolean } }>(`/admin/tool-versions/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(body),
    }),

  recordToolDownload: (id: string) =>
    request<{ item: { id: string; downloadCount: number } }>(`/admin/tool-versions/${id}/download`, {
      method: 'POST',
      body: JSON.stringify({}),
    }),

  setCreatorAccess: (userId: string, active: boolean) =>
    request<{ user: { id: string; creatorKeyId: string | null } }>(`/admin/users/${userId}/creator-access`, {
      method: 'PATCH',
      body: JSON.stringify({ active }),
    }),

  deleteVideo: (videoId: string) =>
    request<void>(`/admin/videos/${videoId}`, {
      method: 'DELETE',
    }),

  verifyNow: (videoId: string, body?: { force?: boolean; allowKeyFallback?: boolean; allowAdminOverrideOnFailure?: boolean }) =>
    request<{
      videoId: string;
      status: 'verified' | 'failed' | 'skipped';
      ok: boolean;
      reason?: string;
      reasons: Array<{
        code: string;
        severity: string;
        message: string;
        platformAction: string;
        creatorAction: string;
      }>;
      video?: import('../types').VideoMeta;
    }>(`/admin/videos/${videoId}/verify-now`, {
      method: 'POST',
      body: JSON.stringify(body ?? {}),
    }),

  verifyBulk: (body?: {
    limit?: number;
    unverifiedOnly?: boolean;
    creatorId?: string;
    startDate?: string;
    endDate?: string;
    allowKeyFallback?: boolean;
    allowAdminOverrideOnFailure?: boolean;
    videoIds?: string[];
  }) =>
    request<{
      processed: number;
      verified: number;
      failed: number;
      skipped: number;
      details: Array<{ videoId: string; title: string; status: 'verified' | 'failed' | 'skipped'; reason?: string }>;
    }>('/admin/videos/verify-bulk', {
      method: 'POST',
      body: JSON.stringify(body ?? {}),
    }),

  recheckRevocations: (body?: {
    limit?: number;
    creatorId?: string;
    startDate?: string;
    endDate?: string;
    onlyVerified?: boolean;
    videoIds?: string[];
  }) =>
    request<{
      checked: number;
      stillVerified: number;
      revokedOrInvalid: number;
      failed: number;
      skipped: number;
      details: Array<{
        videoId: string;
        title: string;
        status: 'verified' | 'failed' | 'skipped';
        revokedOrInvalid?: boolean;
        reason?: string;
      }>;
    }>('/admin/videos/recheck-revocations', {
      method: 'POST',
      body: JSON.stringify(body ?? {}),
    }),

  // Backward-compatible wrappers.
  reverifyVideo: (videoId: string, body?: { force?: boolean }) =>
    adminApi.verifyNow(videoId, body),

  reverifyFailedVideos: (body?: { limit?: number; includeVerified?: boolean }) =>
    adminApi.verifyBulk({
      limit: body?.limit,
      unverifiedOnly: !(body?.includeVerified ?? false),
    }),

  setUserBan: (userId: string, banned: boolean) =>
    request<{ userId: string; banned: boolean }>(`/admin/users/${userId}/ban`, {
      method: 'PATCH',
      body: JSON.stringify({ banned }),
    }),

  setUserAdmin: (userId: string, active: boolean) =>
    request<{ userId: string; isAdmin: boolean }>(`/admin/users/${userId}/admin`, {
      method: 'PATCH',
      body: JSON.stringify({ active }),
    }),

  resolveReport: (reportId: string) =>
    request<{ item: { id: string; status: 'open' | 'resolved' } }>(`/admin/reports/${reportId}`, {
      method: 'PATCH',
      body: JSON.stringify({ action: 'resolve' }),
    }),

  reverifyFailedBundles: (body?: { limit?: number; includeVerified?: boolean }) =>
    adminApi.reverifyFailedVideos(body),

  usageCsvUrl: () => `${BASE}/admin/export/usage.csv`,
  billingCsvUrl: () => `${BASE}/admin/export/billing.csv`,

  getPayoutConfig: () =>
    request<{
      config: {
        enabled: boolean;
        thresholds: {
          minMonthlyNetProfit: number;
          minMonthlyRevenue: number;
          minActiveMonthlyUsers: number;
          minActiveCreators: number;
          minMonthlyApiVerifications: number;
        };
        percentages: {
          subscriptionRevenuePct: number;
          apiUsageRevenuePct: number;
          boostRevenuePct: number;
          monthlyProfitPct: number;
        };
      };
    }>('/admin/payouts/config'),

  updatePayoutConfig: (body: {
    enabled?: boolean;
    thresholds?: Partial<{
      minMonthlyNetProfit: number;
      minMonthlyRevenue: number;
      minActiveMonthlyUsers: number;
      minActiveCreators: number;
      minMonthlyApiVerifications: number;
    }>;
    percentages?: Partial<{
      subscriptionRevenuePct: number;
      apiUsageRevenuePct: number;
      boostRevenuePct: number;
      monthlyProfitPct: number;
    }>;
  }) =>
    request<{ config: unknown }>('/admin/payouts/config', {
      method: 'PATCH',
      body: JSON.stringify(body),
    }),

  runMonthlyPayout: (body: {
    monthKey: string;
    totalRevenue: number;
    infrastructureCost: number;
    operatingCost: number;
    subscriptionRevenue: number;
    apiUsageRevenue: number;
    boostRevenue: number;
    activeMonthlyUsers: number;
    activeCreators: number;
    monthlyApiVerifications: number;
  }) =>
    request<{ item: unknown }>('/admin/payouts/run', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  listPayoutHistory: (limit = 24) =>
    request<{ items: unknown[] }>(`/admin/payouts/history?limit=${Math.max(1, limit)}`),

  listPayoutFlags: () =>
    request<{ items: Array<{ userId: string; reason: string; status: 'open' | 'reviewed' | 'cleared'; updatedAt: string }> }>('/admin/payouts/flags'),

  upsertPayoutFlag: (userId: string, body: { reason: string; status?: 'open' | 'reviewed' | 'cleared' }) =>
    request<{ item: unknown }>(`/admin/payouts/flags/${userId}`, {
      method: 'PATCH',
      body: JSON.stringify(body),
    }),

  getRecommendationConfig: () =>
    request<{
      config: {
        weights: {
          interest: number;
          community: number;
          provenance: number;
          health: number;
          equity: number;
        };
        fairnessRotationFrequency: number;
        creatorDominanceCap: number;
        spotlightBoostVisibility: number;
        healthDownrankThreshold: number;
        aiAdaptiveEnabled: boolean;
      };
    }>('/admin/recommendation/config'),

  updateRecommendationConfig: (body: {
    weights?: Partial<{ interest: number; community: number; provenance: number; health: number; equity: number }>;
    fairnessRotationFrequency?: number;
    creatorDominanceCap?: number;
    spotlightBoostVisibility?: number;
    healthDownrankThreshold?: number;
    aiAdaptiveEnabled?: boolean;
  }) =>
    request<{ config: unknown }>('/admin/recommendation/config', {
      method: 'PATCH',
      body: JSON.stringify(body),
    }),
};

// Origin Protocol
export const originApi = {
  verify: (body: {
    creatorId: string;
    keyId: string;
    assetId: string;
    originId?: string;
    contentHash: string;
  }) =>
    request<import('../types').OriginVerifyResult>('/origin/verify', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  keyStatus: (creatorId: string, keyId: string) =>
    request<{ ok: boolean; keyStatus: string | null }>(`/origin/key-status?creatorId=${creatorId}&keyId=${keyId}`),
};

export const studioApi = {
  getPricing: () =>
    request<{
      plans: Record<string, unknown>;
      creditPacks: Array<{ usd: number; credits: number }>;
      creditCosts: Record<string, unknown>;
    }>('/studio/pricing'),

  listFeatures: () =>
    request<{
      features: Array<{
        key: string;
        label: string;
        phase: 'phase1' | 'phase2' | 'phase3';
        kind: 'basic' | 'assist' | 'generate';
        providers: string[];
        estimateSeconds: number;
        billableCredits: number;
      }>;
      phases: Record<string, string>;
    }>('/studio/features'),

  getCredits: () =>
    request<{
      credits: {
        tier: 'free' | 'creator' | 'pro' | 'enterprise';
        remaining: number;
        reserved: number;
        monthlyLimit: number;
      };
    }>('/studio/credits'),

  signUpload: (body?: { extension?: string; mimeType?: string }) =>
    request<{
      upload: {
        mediaKey: string;
        method: 'PUT';
        contentType: string;
        signedUrl: string;
        expiresInSeconds: number;
      };
    }>('/studio/uploads/sign', {
      method: 'POST',
      body: JSON.stringify(body ?? {}),
    }),

  uploadToSignedUrl: async (
    upload: { signedUrl: string; method: 'PUT'; contentType: string },
    file: File
  ) => {
    const targetUrl = resolveApiUrl(upload.signedUrl);
    const res = await fetch(targetUrl, {
      method: upload.method,
      headers: {
        'Content-Type': upload.contentType || file.type || 'application/octet-stream',
      },
      body: file,
    });

    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(text || `Studio upload failed (HTTP ${res.status})`);
    }
  },

  createJob: (body: {
    feature: string;
    mediaKey?: string;
    prompt?: string;
    options?: Record<string, unknown>;
    preferredProvider?: string;
  }) =>
    request<{ job: unknown }>('/studio/jobs', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  generate: (body: {
    prompt: string;
    tier?: 'free' | 'paid';
    options?: Record<string, unknown>;
  }) =>
    request<{ job: unknown }>('/studio/generate', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  edit: (body: {
    mediaKey: string;
    editType: 'motion' | 'stylization' | 're_timing';
    tier?: 'free' | 'paid';
    options?: Record<string, unknown>;
  }) =>
    request<{ job: unknown }>('/studio/edit', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  listJobs: (status?: 'queued' | 'running' | 'succeeded' | 'failed' | 'canceled') => {
    const query = status ? `?status=${status}` : '';
    return request<{ items: unknown[] }>(`/studio/jobs${query}`);
  },

  getJob: (id: string) =>
    request<{ job: unknown }>(`/studio/jobs/${encodeURIComponent(id)}`),

  getJobStatus: (id: string) =>
    request<{ job: unknown }>(`/studio/job/${encodeURIComponent(id)}`),

  cancelJob: (id: string) =>
    request<{ job: unknown }>(`/studio/jobs/${encodeURIComponent(id)}/cancel`, {
      method: 'POST',
      body: JSON.stringify({}),
    }),
};

function mockSocial(platform: 'youtube' | 'tiktok' | 'x'): { platform: 'youtube' | 'tiktok' | 'x'; items: import('../types').SocialSignal[] } {
  const now = Date.now();
  const suffix = platform.toUpperCase();
  const base: import('../types').SocialSignal[] = [
    { id: `${platform}-watch-1`, platform, type: 'watch', title: `${suffix}: watched creator interview`, createdAt: new Date(now - 45 * 60_000).toISOString() },
    { id: `${platform}-search-1`, platform, type: 'search', title: `${suffix}: searched productivity systems`, createdAt: new Date(now - 3 * 60 * 60_000).toISOString() },
    { id: `${platform}-like-1`, platform, type: 'like', title: `${suffix}: liked short-form editing tips`, createdAt: new Date(now - 26 * 60 * 60_000).toISOString() },
  ];
  return { platform, items: base };
}

export const socialApi = {
  youtube: async () => {
    try {
      return await request<{ platform: 'youtube'; items: import('../types').SocialSignal[] }>('/social/youtube');
    } catch {
      return mockSocial('youtube');
    }
  },

  tiktok: async () => {
    try {
      return await request<{ platform: 'tiktok'; items: import('../types').SocialSignal[] }>('/social/tiktok');
    } catch {
      return mockSocial('tiktok');
    }
  },

  x: async () => {
    try {
      return await request<{ platform: 'x'; items: import('../types').SocialSignal[] }>('/social/x');
    } catch {
      return mockSocial('x');
    }
  },
};

export const abigailApi = {
  chat: async (params: {
    userId: string;
    sessionId?: string;
    message: string;
    history: import('../types').AbigailChatMessage[];
    profileSettings: import('../types').AbigailProfileSettings;
  }): Promise<{ reply: string; offline: boolean; sessionId: string; statusCode: number | null }> => {
    const resolvedSessionId = params.sessionId ?? getOrCreateAbigailSessionId(params.userId);
    try {
      const response = await requestAbigail<{ reply?: string; message?: string; response?: string; session_id?: string; sessionId?: string }>({
        path: '/chat',
        method: 'POST',
        userId: params.userId,
        sessionId: resolvedSessionId,
        body: {
          user_id: params.userId,
          message: params.message,
        },
      });

      const reply = response.data.reply ?? response.data.message ?? response.data.response ?? 'Message received.';
      return {
        reply,
        offline: false,
        sessionId: response.data.session_id ?? response.data.sessionId ?? resolvedSessionId,
        statusCode: response.status,
      };
    } catch (error) {
      if (!isAbigailOfflineFailure(error)) {
        throw error;
      }
      return {
        reply: 'Abigail is temporarily offline. I saved your message locally and will sync when available.',
        offline: true,
        sessionId: resolvedSessionId,
        statusCode: getAbigailErrorStatus(error),
      };
    }
  },

  updateMemory: async (params: {
    userId: string;
    sessionId?: string;
    events: import('../types').AbigailMemoryEvent[];
    profileSettings?: import('../types').AbigailProfileSettings;
  }): Promise<{ ok: boolean; offline: boolean; statusCode: number | null; skipped: number; ingested: number }> => {
    const resolvedSessionId = params.sessionId ?? getOrCreateAbigailSessionId(params.userId);
    try {
      const response = await requestAbigail<{
        ok?: boolean;
        accepted?: boolean;
        ingested?: number;
        accepted_count?: number;
        skipped?: number;
        skipped_records?: number;
        skipped_count?: number;
        memory_updates?: { skipped?: number; created?: string[]; updated?: string[] };
      }>({
        path: '/memory/ingest',
        method: 'POST',
        userId: params.userId,
        sessionId: resolvedSessionId,
        body: {
          user_id: params.userId,
          events: params.events,
          memory_patch: {
            events: params.events,
            profile_settings: params.profileSettings,
            session_id: resolvedSessionId,
          },
        },
      });
      const createdCount = Array.isArray(response.data.memory_updates?.created) ? response.data.memory_updates!.created!.length : 0;
      const updatedCount = Array.isArray(response.data.memory_updates?.updated) ? response.data.memory_updates!.updated!.length : 0;
      const skipped = Number(
        response.data.skipped
        ?? response.data.skipped_records
        ?? response.data.skipped_count
        ?? response.data.memory_updates?.skipped
        ?? 0
      );
      const ingested = Number(response.data.ingested ?? response.data.accepted_count ?? (createdCount + updatedCount));
      return {
        ok: Boolean(response.data.ok ?? response.data.accepted ?? true),
        offline: false,
        statusCode: response.status,
        skipped: Number.isFinite(skipped) ? skipped : 0,
        ingested: Number.isFinite(ingested) ? ingested : 0,
      };
    } catch (error) {
      if (!isAbigailOfflineFailure(error)) {
        throw error;
      }
      return { ok: false, offline: true, statusCode: getAbigailErrorStatus(error), skipped: 0, ingested: 0 };
    }
  },

  memorySnapshot: async (params: {
    userId: string;
    sessionId?: string;
  }): Promise<{ events: import('../types').AbigailMemoryEvent[]; offline: boolean; statusCode: number | null }> => {
    const resolvedSessionId = params.sessionId ?? getOrCreateAbigailSessionId(params.userId);
    try {
      const res = await requestAbigail<{ events?: import('../types').AbigailMemoryEvent[]; items?: import('../types').AbigailMemoryEvent[] }>({
        path: '/memory/snapshot',
        method: 'GET',
        userId: params.userId,
        sessionId: resolvedSessionId,
        query: { user_id: params.userId },
      });
      return { events: res.data.events ?? res.data.items ?? [], offline: false, statusCode: res.status };
    } catch (error) {
      if (!isAbigailOfflineFailure(error)) {
        throw error;
      }
      return { events: [], offline: true, statusCode: getAbigailErrorStatus(error) };
    }
  },

  recommendations: async (params: {
    userId: string;
    sessionId?: string;
  }): Promise<{ items: import('../types').AbigailRecommendation[]; offline: boolean; statusCode: number | null }> => {
    const resolvedSessionId = params.sessionId ?? getOrCreateAbigailSessionId(params.userId);
    try {
      const res = await requestAbigail<{ items?: import('../types').AbigailRecommendation[]; recommendations?: import('../types').AbigailRecommendation[] }>({
        path: '/recommendations',
        method: 'GET',
        userId: params.userId,
        sessionId: resolvedSessionId,
        query: { user_id: params.userId },
      });
      return { items: res.data.items ?? res.data.recommendations ?? [], offline: false, statusCode: res.status };
    } catch (error) {
      if (!isAbigailOfflineFailure(error)) {
        throw error;
      }
      return {
        offline: true,
        statusCode: getAbigailErrorStatus(error),
        items: [
          { id: 'offline-video-1', kind: 'video', title: 'Creator workflow checklist', reason: 'Fallback recommendation while Abigail is offline.' },
          { id: 'offline-task-1', kind: 'task', title: 'Write three intent signals for Abigail memory', reason: 'Helps bootstrap personalization quickly.' },
        ],
      };
    }
  },

  memoryContext: async (params: {
    userId: string;
    query?: string;
    limit?: number;
  }): Promise<{ bundle: string[]; memories: Array<Record<string, unknown>>; statusCode: number | null }> => {
    const res = await requestAbigail<{ bundle?: string[]; memories?: Array<Record<string, unknown>>; context_bundle?: string[] }>({
      path: '/memory/context',
      method: 'GET',
      userId: params.userId,
      query: {
        user_id: params.userId,
        ...(params.query ? { query: params.query } : {}),
        ...(params.limit ? { limit: String(params.limit) } : {}),
      },
    });

    return {
      bundle: res.data.bundle ?? res.data.context_bundle ?? [],
      memories: res.data.memories ?? [],
      statusCode: res.status,
    };
  },

  forgetMemory: async (params: {
    userId: string;
    type?: string;
    source?: string;
    beforeTs?: string;
    anonymize?: boolean;
    hardDelete?: boolean;
  }): Promise<{ ok: boolean; affectedMemories?: number; affectedEvents?: number; statusCode: number | null }> => {
    const res = await requestAbigail<{ ok?: boolean; affectedMemories?: number; affectedEvents?: number }>({
      path: '/memory/forget',
      method: 'POST',
      userId: params.userId,
      body: {
        user_id: params.userId,
        ...(params.type ? { type: params.type } : {}),
        ...(params.source ? { source: params.source } : {}),
        ...(params.beforeTs ? { before_ts: params.beforeTs } : {}),
        ...(params.anonymize !== undefined ? { anonymize: params.anonymize } : {}),
        ...(params.hardDelete !== undefined ? { hard_delete: params.hardDelete } : {}),
      },
    });

    return {
      ok: Boolean(res.data.ok ?? true),
      affectedMemories: res.data.affectedMemories,
      affectedEvents: res.data.affectedEvents,
      statusCode: res.status,
    };
  },

  exportMemory: async (params: {
    userId: string;
  }): Promise<{ payload: Record<string, unknown>; statusCode: number | null }> => {
    const res = await requestAbigail<Record<string, unknown>>({
      path: '/memory/export',
      method: 'GET',
      userId: params.userId,
      query: { user_id: params.userId },
    });

    return {
      payload: res.data ?? {},
      statusCode: res.status,
    };
  },
};

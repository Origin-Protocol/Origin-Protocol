const BASE = '/api';

function getToken(): string | null {
  return localStorage.getItem('origin_token');
}

function headers(extra: Record<string, string> = {}): Record<string, string> {
  const h: Record<string, string> = { 'Content-Type': 'application/json', ...extra };
  const t = getToken();
  if (t) h['Authorization'] = `Bearer ${t}`;
  return h;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: { ...headers(), ...(init.headers as Record<string, string> | undefined) },
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error((body as { error?: string }).error ?? `HTTP ${res.status}`);
  }

  return res.json() as Promise<T>;
}

// Auth
export const authApi = {
  register: (body: { username: string; email: string; password: string; displayName?: string }) =>
    request<{ user: import('../types').User; token: string }>('/auth/register', {
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
  get: (page = 1, pageSize = 20) =>
    request<import('../types').PaginatedResponse<import('../types').VideoMeta>>(
      `/feed?page=${page}&pageSize=${pageSize}`
    ),
};

// Videos
export const videosApi = {
  get: (id: string) =>
    request<{ video: import('../types').VideoMeta }>(`/videos/${id}`),

  upload: (formData: FormData) => {
    const token = getToken();
    return fetch(`${BASE}/videos`, {
      method: 'POST',
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      body: formData,
    }).then(async (res) => {
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error((body as { error?: string }).error ?? `HTTP ${res.status}`);
      }
      return res.json() as Promise<{ video: import('../types').VideoMeta }>;
    });
  },

  delete: (id: string) =>
    request<void>(`/videos/${id}`, { method: 'DELETE' }),

  like: (id: string) =>
    request<{ liked: boolean }>(`/videos/${id}/like`, { method: 'POST' }),

  getComments: (id: string) =>
    request<{ comments: import('../types').Comment[] }>(`/videos/${id}/comments`),

  postComment: (id: string, text: string) =>
    request<{ comment: import('../types').Comment }>(`/videos/${id}/comments`, {
      method: 'POST',
      body: JSON.stringify({ text }),
    }),
};

// Users
export const usersApi = {
  getProfile: (id: string) =>
    request<{ user: import('../types').User }>(`/users/${id}`),

  updateMe: (body: { displayName?: string; bio?: string; creatorKeyId?: string }) =>
    request<{ user: import('../types').User }>('/users/me', {
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
    request<{ ok: boolean; reasons: unknown[] }>('/origin/verify', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  keyStatus: (creatorId: string, keyId: string) =>
    request<{ ok: boolean; keyStatus: string | null }>(`/origin/key-status?creatorId=${creatorId}&keyId=${keyId}`),
};

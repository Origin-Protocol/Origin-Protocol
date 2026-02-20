import * as SecureStore from 'expo-secure-store';

// Change to your server's IP/hostname when running on a physical device
const BASE_URL = process.env.EXPO_PUBLIC_API_URL ?? 'http://localhost:4000/api';

async function getToken(): Promise<string | null> {
  return SecureStore.getItemAsync('origin_token');
}

async function buildHeaders(extra: Record<string, string> = {}): Promise<Record<string, string>> {
  const h: Record<string, string> = { 'Content-Type': 'application/json', ...extra };
  const t = await getToken();
  if (t) h['Authorization'] = `Bearer ${t}`;
  return h;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = await buildHeaders();
  const res = await fetch(`${BASE_URL}${path}`, {
    ...init,
    headers: { ...headers, ...(init.headers as Record<string, string> | undefined) },
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error((body as { error?: string }).error ?? `HTTP ${res.status}`);
  }

  return res.json() as Promise<T>;
}

// Auth
export const authApi = {
  async register(body: { username: string; email: string; password: string; displayName?: string }) {
    const data = await request<{ user: import('../types').User; token: string }>('/auth/register', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    await SecureStore.setItemAsync('origin_token', data.token);
    await SecureStore.setItemAsync('origin_user', JSON.stringify(data.user));
    return data;
  },

  async login(body: { email: string; password: string }) {
    const data = await request<{ user: import('../types').User; token: string }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    await SecureStore.setItemAsync('origin_token', data.token);
    await SecureStore.setItemAsync('origin_user', JSON.stringify(data.user));
    return data;
  },

  async logout() {
    await SecureStore.deleteItemAsync('origin_token');
    await SecureStore.deleteItemAsync('origin_user');
  },

  async getStoredUser(): Promise<import('../types').User | null> {
    const raw = await SecureStore.getItemAsync('origin_user');
    return raw ? (JSON.parse(raw) as import('../types').User) : null;
  },
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

  async upload(params: { uri: string; title: string; description?: string; originBundleId?: string }) {
    const token = await getToken();
    const fd = new FormData();
    // React Native FormData accepts objects with uri/name/type
    fd.append('video', { uri: params.uri, name: 'video.mp4', type: 'video/mp4' } as unknown as Blob);
    fd.append('title', params.title);
    if (params.description) fd.append('description', params.description);
    if (params.originBundleId) fd.append('originBundleId', params.originBundleId);

    const res = await fetch(`${BASE_URL}/videos`, {
      method: 'POST',
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      body: fd,
    });

    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error((body as { error?: string }).error ?? `HTTP ${res.status}`);
    }

    return res.json() as Promise<{ video: import('../types').VideoMeta }>;
  },

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

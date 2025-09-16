// In dev, point to backend on 8080 unless overridden by VITE_API_ORIGIN.
const __env: any = (import.meta as any).env || {};
const API_ORIGIN =
  __env.VITE_API_ORIGIN ?? (__env.DEV ? "http://localhost:8080" : "");
export const API_BASE = `${API_ORIGIN}/v1`;

let authToken: string | undefined;
export function setAuthToken(t?: string) {
  authToken = t;
}

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...((init?.headers as any) || {}),
  };
  if (authToken) headers["Authorization"] = `Bearer ${authToken}`;
  const res = await fetch(`${API_BASE}${path}`, {
    credentials: "include",
    headers,
    ...init,
  });
  if (!res.ok) throw new Error(`API ${res.status}`);
  if (res.status === 204) return undefined as unknown as T;
  return (await res.json()) as T;
}

export type ListItem = { item_id: string; updated_at: number; size: number };
export async function listItems(limit = 50, cursor?: string) {
  const qs = new URLSearchParams();
  qs.set("limit", String(limit));
  if (cursor) qs.set("cursor", cursor);
  return api<{ items: ListItem[]; next_cursor?: string }>(`/items/list?${qs}`);
}

export async function getItems(ids: string[]) {
  const qs = new URLSearchParams();
  qs.set("ids", ids.join(","));
  return api<Array<{ item_id: string; ciphertext: string }>>(`/items?${qs}`);
}

export async function createItem(body: {
  item_id: string;
  version?: number;
  ciphertext_b64: string;
  tokens?: Record<string, string[]>;
}) {
  return api<{ item_id: string; version: number }>(`/items`, {
    method: "POST",
    body: JSON.stringify({ version: 1, tokens: {}, ...body }),
  });
}

export async function updateItem(
  id: string,
  body: {
    expected_version?: number;
    version?: number;
    ciphertext_b64: string;
    tokens?: Record<string, string[]>;
  },
) {
  return api<void>(`/items/${encodeURIComponent(id)}`, {
    method: "PUT",
    body: JSON.stringify({ version: 1, tokens: {}, ...body }),
  });
}

export async function deleteItem(id: string) {
  return api<void>(`/items/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export async function searchEq(
  tokens: Array<{ type: string; value_b64: string }>,
  limit = 50,
  cursor?: string,
) {
  return api<{ item_ids: string[]; next_cursor?: string }>(`/search/eq`, {
    method: "POST",
    body: JSON.stringify({ tokens, limit, cursor }),
  });
}

// Auth stubs (backend not implemented yet)
export async function authRegister(body: {
  username: string;
  password: string;
}) {
  return api<{ otpauth_url: string }>(`/auth/register`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}
export async function authLogin(body: {
  username: string;
  password: string;
  code: string;
}) {
  return api<{ token: string; username: string }>(`/auth/login`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}
export async function authMFAVerify(body: {
  username: string;
  password: string;
  code: string;
}) {
  return api<void>(`/auth/mfa/verify`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}
export async function authMe() {
  return api<{ username: string }>(`/auth/me`, { method: "GET" });
}
export async function authLogout() {
  return api<void>(`/auth/logout`, { method: "POST" });
}

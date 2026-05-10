// Auth store. Persists session-level state (tokens, user_id, device_id)
// via localStorage so a refresh keeps the user signed in. Vault-level state
// (vault_key, master_key) is *not* persisted and lives in stores/vault.ts.

import { create } from "zustand";
import { persist } from "zustand/middleware";

export type AuthState = {
  userId: string | null;
  email: string | null;
  accessToken: string | null;
  refreshToken: string | null;
  accessExpiresAt: number | null; // unix millis
  refreshExpiresAt: number | null; // unix millis
  deviceId: string;

  setSession: (s: {
    userId: string;
    email: string;
    accessToken: string;
    refreshToken: string;
    accessExpiresAt: number;
    refreshExpiresAt: number;
  }) => void;
  clear: () => void;
  isAuthenticated: () => boolean;
};

// Stable per-browser identifier so the server can deduplicate sessions per device.
function ensureDeviceId(): string {
  const k = "oblivio.deviceId";
  let v = localStorage.getItem(k);
  if (!v) {
    v = crypto.randomUUID();
    localStorage.setItem(k, v);
  }
  return v;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      userId: null,
      email: null,
      accessToken: null,
      refreshToken: null,
      accessExpiresAt: null,
      refreshExpiresAt: null,
      deviceId:
        typeof window === "undefined"
          ? "ssr-placeholder"
          : ensureDeviceId(),

      setSession: (s) =>
        set({
          userId: s.userId,
          email: s.email,
          accessToken: s.accessToken,
          refreshToken: s.refreshToken,
          accessExpiresAt: s.accessExpiresAt,
          refreshExpiresAt: s.refreshExpiresAt,
        }),

      clear: () =>
        set({
          userId: null,
          email: null,
          accessToken: null,
          refreshToken: null,
          accessExpiresAt: null,
          refreshExpiresAt: null,
        }),

      isAuthenticated: () => {
        const t = get().accessToken;
        const exp = get().accessExpiresAt;
        return !!t && !!exp && exp > Date.now();
      },
    }),
    {
      name: "oblivio.auth",
      partialize: (s) => ({
        userId: s.userId,
        email: s.email,
        accessToken: s.accessToken,
        refreshToken: s.refreshToken,
        accessExpiresAt: s.accessExpiresAt,
        refreshExpiresAt: s.refreshExpiresAt,
        deviceId: s.deviceId,
      }),
    },
  ),
);

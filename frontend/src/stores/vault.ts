// Vault store. Holds in-memory references to the unwrapped vault_key and a
// derived blind-index key. NOT persisted — refreshing the page re-locks the
// vault and the user must re-enter master_password.

import { create } from "zustand";

export type VaultState = {
  vaultKey: Uint8Array | null;
  vaultKeyVersion: number | null;

  setVaultKey: (key: Uint8Array, version: number) => void;
  lock: () => void;
  isUnlocked: () => boolean;
};

export const useVaultStore = create<VaultState>()((set, get) => ({
  vaultKey: null,
  vaultKeyVersion: null,

  setVaultKey: (key, version) =>
    set({ vaultKey: key, vaultKeyVersion: version }),

  lock: () => {
    // Best-effort wipe before dropping the reference.
    const k = get().vaultKey;
    if (k) k.fill(0);
    set({ vaultKey: null, vaultKeyVersion: null });
  },

  isUnlocked: () => get().vaultKey !== null,
}));

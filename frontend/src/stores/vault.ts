// Vault store. Holds in-memory references to the unwrapped vault_key, its
// version, and the per-user blind-index pepper. NOT persisted — refreshing
// the page re-locks the vault and the user must re-enter master_password.

import { create } from "zustand"

export type VaultState = {
  vaultKey: Uint8Array | null
  vaultKeyVersion: number | null
  blindPepper: Uint8Array | null

  setVaultKey: (
    key: Uint8Array,
    version: number,
    blindPepper: Uint8Array
  ) => void
  lock: () => void
  isUnlocked: () => boolean
}

export const useVaultStore = create<VaultState>()((set, get) => ({
  vaultKey: null,
  vaultKeyVersion: null,
  blindPepper: null,

  setVaultKey: (key, version, blindPepper) =>
    set({ vaultKey: key, vaultKeyVersion: version, blindPepper }),

  lock: () => {
    // Best-effort wipe before dropping the reference.
    const k = get().vaultKey
    if (k) k.fill(0)
    const p = get().blindPepper
    if (p) p.fill(0)
    set({ vaultKey: null, vaultKeyVersion: null, blindPepper: null })
  },

  isUnlocked: () => get().vaultKey !== null,
}))

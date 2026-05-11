// Unlock screen — re-derive vault_key from master_password without
// dropping the access token. We use the same KDF params returned by
// /authorize but skip the network call by reading GetMyKeys for the
// stored verifier + wrapped_vault_key.

import { useState } from "react"
import { useNavigate } from "@tanstack/react-router"

import { authClient, vaultClient } from "@/api/client"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useAuthStore } from "@/stores/auth"
import { useVaultStore } from "@/stores/vault"
import {
  checkVerifier,
  deriveAuthKey,
  deriveMasterKey,
  importMasterKey,
  unwrapVaultKey,
  type Argon2Params,
} from "@oblivio/crypto"

export default function UnlockPage() {
  const navigate = useNavigate()
  const email = useAuthStore((s) => s.email)
  const setVaultKey = useVaultStore((s) => s.setVaultKey)
  const clearSession = useAuthStore((s) => s.clear)
  const lockVault = useVaultStore((s) => s.lock)

  const [password, setPassword] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleUnlock(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    if (!email) {
      setError("session expired — sign in again")
      return
    }
    setBusy(true)
    try {
      const kdf = await authClient.getKDFParams({ email })
      if (!kdf.kdfParams) throw new Error("server returned no kdf params")
      const params: Argon2Params = {
        t: kdf.kdfParams.t,
        mKib: kdf.kdfParams.mKib,
        p: Math.max(1, kdf.kdfParams.p),
        algo: kdf.kdfParams.algo,
      }
      const masterKeyRaw = await deriveMasterKey(password, kdf.saltUser, params)
      const masterKey = await importMasterKey(masterKeyRaw)
      // auth_key derivation kept for parity with login flow even though
      // unlock does not need to round-trip it.
      await deriveAuthKey(masterKeyRaw, kdf.saltUser)

      const keys = await authClient.getMyKeys({})
      if (!(await checkVerifier(masterKey, keys.verifier))) {
        throw new Error("wrong master password")
      }
      const vaultKey = await unwrapVaultKey(masterKey, keys.wrappedVaultKey)
      setVaultKey(vaultKey, keys.vaultKeyVersion, kdf.blindPepper)
      masterKeyRaw.fill(0)

      // Refresh the canonical user_id; it backs the AAD vault scope, so a
      // stale or missing value would silently mangle decryption.
      const me = await vaultClient.getMe({})
      useAuthStore.setState({ userId: me.userId, email: me.email })

      await navigate({ to: "/app" })
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  function handleSignOut() {
    lockVault()
    clearSession()
    void navigate({ to: "/login" })
  }

  return (
    <form onSubmit={handleUnlock} className="space-y-4">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold">Unlock vault</h1>
        <p className="text-sm text-muted-foreground">
          {email
            ? `Signed in as ${email}. Re-enter your master password to unlock.`
            : "No session — sign in below."}
        </p>
      </div>
      <div className="space-y-2">
        <Label htmlFor="password">Master password</Label>
        <Input
          id="password"
          type="password"
          autoComplete="current-password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </div>
      {error && <p className="text-sm text-destructive">{error}</p>}
      <div className="flex gap-2">
        <Button type="submit" className="flex-1" disabled={busy || !email}>
          {busy ? "Unlocking…" : "Unlock"}
        </Button>
        <Button type="button" variant="ghost" onClick={handleSignOut}>
          Sign out
        </Button>
      </div>
    </form>
  )
}

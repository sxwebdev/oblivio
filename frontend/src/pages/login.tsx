// Login page. Fetches per-user KDF params, re-derives master_key on the
// client, sends auth_key to the server, unwraps vault_key locally on response.

import { useState } from "react"
import { Link, useNavigate } from "@tanstack/react-router"
import {
  checkVerifier,
  deriveAuthKey,
  deriveMasterKey,
  importMasterKey,
  unwrapVaultKey,
  type Argon2Params,
} from "@oblivio/crypto"

import { authClient, vaultClient } from "@/api/client"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { useAuthStore } from "@/stores/auth"
import { useVaultStore } from "@/stores/vault"

export default function LoginPage() {
  const navigate = useNavigate()
  const setSession = useAuthStore((s) => s.setSession)
  const setVaultKey = useVaultStore((s) => s.setVaultKey)
  const deviceId = useAuthStore((s) => s.deviceId)

  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      const kdf = await authClient.getKDFParams({ email })
      if (!kdf.kdfParams) throw new Error("server returned no kdf params")
      const params: Argon2Params = {
        t: kdf.kdfParams.t,
        mKib: kdf.kdfParams.mKib,
        p: Math.max(1, kdf.kdfParams.p), // p=0 should fall back to 1
        algo: kdf.kdfParams.algo,
      }
      const masterKeyRaw = await deriveMasterKey(password, kdf.saltUser, params)
      const masterKey = await importMasterKey(masterKeyRaw)
      const authKey = await deriveAuthKey(masterKeyRaw, email)

      const resp = await authClient.authorize({
        email,
        authKey,
        deviceInfo: {
          deviceId,
          deviceType: "web",
          deviceName: navigator.userAgent.slice(0, 64),
        },
      })
      const payload = resp.authPayload
      if (!payload) throw new Error("invalid credentials")

      // Sanity check master_key derivation by decrypting the verifier.
      if (!(await checkVerifier(masterKey, payload.verifier))) {
        throw new Error("verifier check failed — wrong password")
      }

      const vaultKey = await unwrapVaultKey(masterKey, payload.wrappedVaultKey)

      // The Authorize response does not carry user_id (anti-enumeration:
      // we only learn the canonical UUID after issuing the token). Set a
      // provisional session now so vaultClient picks up the Bearer token,
      // then resolve user_id via GetMe — its value is the AAD scope for
      // every encrypted blob, so we MUST have it before unlocking the UI.
      setSession({
        userId: "",
        email,
        accessToken: payload.accessToken,
        refreshToken: payload.refreshToken,
        accessExpiresAt: Number(payload.accessExpiresAt?.seconds ?? 0n) * 1000,
        refreshExpiresAt: Number(payload.refreshExpiresAt?.seconds ?? 0n) * 1000,
      })
      setVaultKey(vaultKey, payload.vaultKeyVersion)
      masterKeyRaw.fill(0)

      const me = await vaultClient.getMe({})
      setSession({
        userId: me.userId,
        email: me.email,
        accessToken: payload.accessToken,
        refreshToken: payload.refreshToken,
        accessExpiresAt: Number(payload.accessExpiresAt?.seconds ?? 0n) * 1000,
        refreshExpiresAt: Number(payload.refreshExpiresAt?.seconds ?? 0n) * 1000,
      })

      navigate({ to: "/app" })
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-2">
        <h1 className="text-2xl font-semibold">Sign in</h1>
        <p className="text-sm text-muted-foreground">
          Your master password is hashed locally; only the derived auth key
          reaches the server.
        </p>
      </div>
      <Input
        type="email"
        placeholder="email"
        autoComplete="email"
        required
        value={email}
        onChange={(e) => setEmail(e.target.value)}
      />
      <Input
        type="password"
        placeholder="master password"
        autoComplete="current-password"
        required
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      {error && <p className="text-sm text-destructive">{error}</p>}
      <Button type="submit" className="w-full" disabled={busy}>
        {busy ? "Unlocking…" : "Sign in"}
      </Button>
      <p className="text-center text-sm text-muted-foreground">
        New here?{" "}
        <Link to="/register" className="text-foreground underline">
          Create a vault
        </Link>
      </p>
    </form>
  )
}

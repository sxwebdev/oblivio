// Registration page. Runs the full client-side zero-knowledge bootstrap and
// posts the encrypted artefacts to AuthService.Register.

import { useState } from "react"
import { Link, useNavigate } from "@tanstack/react-router"
import {
  deriveAuthKey,
  deriveMasterKey,
  generateRecoveryCode,
  deriveRecoveryKey,
  deriveRecoveryProof,
  generateVaultKey,
  importMasterKey,
  makeVerifier,
  randomBytes,
  wrapVaultKey,
  wrapVaultKeyForRecovery,
} from "@oblivio/crypto"

import { authClient } from "@/api/client"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { useAuthStore } from "@/stores/auth"
import { useVaultStore } from "@/stores/vault"

// Per plan §4.2 the client KDF runs t=3, m=128 MiB, p=4. We start at p=1 (no
// multi-threading) since COOP/COEP headers for SharedArrayBuffer would need
// extra setup; this still gives healthy entropy for the threat model.
const KDF = { t: 3, mKib: 131072, p: 1, algo: "argon2id" } as const

export default function RegisterPage() {
  const navigate = useNavigate()
  const setSession = useAuthStore((s) => s.setSession)
  const setVaultKey = useVaultStore((s) => s.setVaultKey)
  const deviceId = useAuthStore((s) => s.deviceId)

  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [recoveryCode, setRecoveryCode] = useState<string | null>(null)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      const saltUser = randomBytes(16)
      const masterKeyRaw = await deriveMasterKey(password, saltUser, KDF)
      const masterKey = await importMasterKey(masterKeyRaw)
      const authKey = await deriveAuthKey(masterKeyRaw, email)
      const vaultKey = generateVaultKey()
      const wrappedVaultKey = await wrapVaultKey(masterKey, vaultKey)
      const verifier = await makeVerifier(masterKey)

      const code = generateRecoveryCode()
      const recoverySalt = randomBytes(16)
      const recoveryKey = await deriveRecoveryKey(code, recoverySalt)
      const recoveryWrappedVaultKey = await wrapVaultKeyForRecovery(
        recoveryKey,
        vaultKey,
      )
      const recoveryProof = await deriveRecoveryProof(recoveryKey)

      const resp = await authClient.register({
        email,
        saltUser,
        kdfParams: { t: KDF.t, mKib: KDF.mKib, p: KDF.p, algo: KDF.algo },
        authKey,
        verifier,
        wrappedVaultKey,
        recoverySalt,
        recoveryWrappedVaultKey,
        recoveryProof,
        deviceInfo: { deviceId, deviceType: "web", deviceName: navigator.userAgent.slice(0, 64) },
      })

      const payload = resp.authPayload
      if (!payload) throw new Error("server returned no auth payload")

      setSession({
        userId: resp.userId,
        email,
        accessToken: payload.accessToken,
        refreshToken: payload.refreshToken,
        accessExpiresAt: Number(payload.accessExpiresAt?.seconds ?? 0n) * 1000,
        refreshExpiresAt: Number(payload.refreshExpiresAt?.seconds ?? 0n) * 1000,
      })
      setVaultKey(vaultKey, payload.vaultKeyVersion)

      // Wipe the raw master_key bytes from memory.
      masterKeyRaw.fill(0)

      setRecoveryCode(code)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  if (recoveryCode) {
    return (
      <div className="space-y-4">
        <h1 className="text-2xl font-semibold">Save your recovery code</h1>
        <p className="text-sm text-muted-foreground">
          This is the only way to recover your vault if you forget your master
          password. We will not show it again.
        </p>
        <pre className="rounded-md border bg-muted p-4 font-mono text-center text-sm">
          {recoveryCode}
        </pre>
        <Button onClick={() => navigate({ to: "/app" })} className="w-full">
          I have saved it — continue
        </Button>
      </div>
    )
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-2">
        <h1 className="text-2xl font-semibold">Create your vault</h1>
        <p className="text-sm text-muted-foreground">
          Your master password never leaves this browser.
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
        autoComplete="new-password"
        required
        minLength={8}
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      {error && <p className="text-sm text-destructive">{error}</p>}
      <Button type="submit" className="w-full" disabled={busy}>
        {busy ? "Creating vault…" : "Register"}
      </Button>
      <p className="text-center text-sm text-muted-foreground">
        Already have an account?{" "}
        <Link to="/login" className="text-foreground underline">
          Sign in
        </Link>
      </p>
    </form>
  )
}

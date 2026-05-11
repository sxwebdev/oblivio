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
  pickArgon2Params,
  randomBytes,
  wrapVaultKey,
  wrapVaultKeyForRecovery,
} from "@oblivio/crypto"

import { authClient } from "@/api/client"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { useAuthStore } from "@/stores/auth"
import { useVaultStore } from "@/stores/vault"

// KDF parameters are device-aware: pickArgon2Params returns the desktop
// profile (m=128 MiB, t=3) or a halved-memory iOS fallback (m=32 MiB, t=8)
// depending on user-agent + navigator.deviceMemory (see plan §17.2). The
// chosen params are frozen into user_kdf_params at Register time; the user
// keeps them for every subsequent login until ChangeMasterPassword.

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
      const blindPepper = randomBytes(16)
      const kdfParams = pickArgon2Params()
      const masterKeyRaw = await deriveMasterKey(password, saltUser, kdfParams)
      const masterKey = await importMasterKey(masterKeyRaw)
      const authKey = await deriveAuthKey(masterKeyRaw, saltUser)
      const vaultKey = generateVaultKey()
      const wrappedVaultKey = await wrapVaultKey(masterKey, vaultKey)
      const verifier = await makeVerifier(masterKey)

      const code = generateRecoveryCode()
      const recoverySalt = randomBytes(16)
      const recoveryKey = await deriveRecoveryKey(code, recoverySalt)
      const recoveryWrappedVaultKey = await wrapVaultKeyForRecovery(
        recoveryKey,
        vaultKey
      )
      const recoveryProof = await deriveRecoveryProof(recoveryKey)

      const resp = await authClient.register({
        email,
        saltUser,
        kdfParams: {
          t: kdfParams.t,
          mKib: kdfParams.mKib,
          p: kdfParams.p,
          algo: kdfParams.algo,
        },
        authKey,
        verifier,
        wrappedVaultKey,
        recoverySalt,
        recoveryWrappedVaultKey,
        recoveryProof,
        blindPepper,
        deviceInfo: {
          deviceId,
          deviceType: "web",
          deviceName: navigator.userAgent.slice(0, 64),
        },
      })

      const payload = resp.authPayload
      if (!payload) throw new Error("server returned no auth payload")

      setSession({
        userId: resp.userId,
        email,
        accessToken: payload.accessToken,
        refreshToken: payload.refreshToken,
        accessExpiresAt: Number(payload.accessExpiresAt?.seconds ?? 0n) * 1000,
        refreshExpiresAt:
          Number(payload.refreshExpiresAt?.seconds ?? 0n) * 1000,
      })
      setVaultKey(vaultKey, payload.vaultKeyVersion, blindPepper)

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
        <pre className="rounded-md border bg-muted p-4 text-center font-mono text-sm">
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

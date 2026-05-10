// Recovery flow. The user enters their email + recovery code, the client
// re-derives recovery_key locally, fetches the recovery-wrapped vault_key,
// decrypts it, then asks for a new master password and re-wraps everything.
// All KDF and AEAD operations happen in the browser — the server only sees
// derived proofs and ciphertext.

import { useState } from "react"
import { Link, useNavigate } from "@tanstack/react-router"
import {
  deriveAuthKey,
  deriveMasterKey,
  deriveRecoveryKey,
  deriveRecoveryProof,
  generateRecoveryCode,
  importMasterKey,
  makeVerifier,
  normalizeRecoveryCode,
  randomBytes,
  unwrapVaultKeyFromRecovery,
  wrapVaultKey,
  type Argon2Params,
} from "@oblivio/crypto"

import { authClient } from "@/api/client"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"

const CLIENT_KDF = { t: 3, mKib: 131072, p: 1, algo: "argon2id" } as const

type Step = "code" | "newpw" | "done"

export default function RecoverPage() {
  const navigate = useNavigate()
  const [step, setStep] = useState<Step>("code")
  const [email, setEmail] = useState("")
  const [code, setCode] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Persisted across step transitions inside the same page session.
  const [sessionId, setSessionId] = useState("")
  const [vaultKey, setVaultKey] = useState<Uint8Array | null>(null)

  const [password, setPassword] = useState("")
  const [confirm, setConfirm] = useState("")
  const [newRecovery, setNewRecovery] = useState<string | null>(null)

  async function handleCodeSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      const params = await authClient.getRecoveryParams({ email })
      if (!params.kdfParams) throw new Error("missing kdf params")
      const recoveryKey = await deriveRecoveryKey(
        normalizeRecoveryCode(code),
        params.recoverySalt,
        params.kdfParams.t,
        params.kdfParams.mKib,
      )
      const proof = await deriveRecoveryProof(recoveryKey)
      const start = await authClient.recoveryStart({
        email,
        recoveryProof: proof,
      })
      const unwrapped = await unwrapVaultKeyFromRecovery(
        recoveryKey,
        start.recoveryWrappedVaultKey,
      )
      setSessionId(start.recoverySessionId)
      setVaultKey(unwrapped)
      setStep("newpw")
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "Invalid recovery code (or this email is unknown).",
      )
    } finally {
      setBusy(false)
    }
  }

  async function handleNewPasswordSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    if (password.length < 8) {
      setError("master password must be at least 8 characters")
      return
    }
    if (password !== confirm) {
      setError("passwords do not match")
      return
    }
    if (!vaultKey) {
      setError("session lost — start over")
      return
    }
    setBusy(true)
    try {
      const saltUser = randomBytes(16)
      const masterKeyRaw = await deriveMasterKey(password, saltUser, CLIENT_KDF)
      const masterKey = await importMasterKey(masterKeyRaw)
      const authKey = await deriveAuthKey(masterKeyRaw, email)
      const verifier = await makeVerifier(masterKey)
      const wrappedVaultKey = await wrapVaultKey(masterKey, vaultKey)

      await authClient.recoveryComplete({
        recoverySessionId: sessionId,
        saltUser,
        kdfParams: {
          t: CLIENT_KDF.t,
          mKib: CLIENT_KDF.mKib,
          p: CLIENT_KDF.p,
          algo: CLIENT_KDF.algo,
        },
        authKey,
        verifier,
        wrappedVaultKey,
      })

      // Generating a fresh recovery code is a UX nicety so the user is not
      // tempted to keep the (now-known-by-someone-else) old one. We surface
      // it as a tip; the actual code is unchanged on the server until the
      // user re-registers (Sprint 4 will add a rotate endpoint).
      setNewRecovery(generateRecoveryCode())
      masterKeyRaw.fill(0)
      vaultKey.fill(0)
      setStep("done")
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  if (step === "done") {
    return (
      <div className="space-y-4">
        <h1 className="text-2xl font-semibold">Password updated</h1>
        <p className="text-sm text-muted-foreground">
          All previous sessions were signed out. Use your new master password
          to sign in.
        </p>
        {newRecovery && (
          <div className="space-y-2">
            <p className="text-sm">
              Suggested new recovery code — write it down before continuing.
              The server still accepts the old one until you regenerate from
              settings.
            </p>
            <pre className="rounded-md border bg-muted p-3 text-center font-mono text-sm">
              {newRecovery}
            </pre>
          </div>
        )}
        <Button className="w-full" onClick={() => navigate({ to: "/login" })}>
          Continue to sign in
        </Button>
      </div>
    )
  }

  if (step === "newpw") {
    return (
      <form onSubmit={handleNewPasswordSubmit} className="space-y-4">
        <div className="space-y-2">
          <h1 className="text-2xl font-semibold">Set a new master password</h1>
          <p className="text-sm text-muted-foreground">
            We recovered your vault key locally. Pick a new password — it never
            leaves this device.
          </p>
        </div>
        <Input
          type="password"
          placeholder="new master password"
          autoComplete="new-password"
          required
          minLength={8}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <Input
          type="password"
          placeholder="confirm master password"
          autoComplete="new-password"
          required
          minLength={8}
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
        />
        {error && <p className="text-sm text-destructive">{error}</p>}
        <Button type="submit" className="w-full" disabled={busy}>
          {busy ? "Re-wrapping vault…" : "Save new password"}
        </Button>
      </form>
    )
  }

  return (
    <form onSubmit={handleCodeSubmit} className="space-y-4">
      <div className="space-y-2">
        <h1 className="text-2xl font-semibold">Recover access</h1>
        <p className="text-sm text-muted-foreground">
          Enter the 25-character recovery code we showed you at registration.
          Decryption happens locally; the server never sees your code.
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
        placeholder="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
        autoComplete="off"
        required
        value={code}
        onChange={(e) => setCode(e.target.value)}
      />
      {error && <p className="text-sm text-destructive">{error}</p>}
      <Button type="submit" className="w-full" disabled={busy}>
        {busy ? "Verifying…" : "Continue"}
      </Button>
      <p className="text-center text-sm text-muted-foreground">
        Remembered it after all?{" "}
        <Link to="/login" className="text-foreground underline">
          Sign in
        </Link>
      </p>
    </form>
  )
}

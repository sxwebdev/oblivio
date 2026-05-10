// Login page. Fetches per-user KDF params, re-derives master_key on the
// client, sends auth_key to the server, unwraps vault_key locally on response.
//
// When the server replies with an MFAChallenge instead of an AuthPayload we
// render a second-step form (TOTP code or passkey button) and call
// CompleteMFA to obtain the final auth payload.

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
import {
  startAuthentication,
  type PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser"

import { authClient, vaultClient } from "@/api/client"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { useAuthStore } from "@/stores/auth"
import { useVaultStore } from "@/stores/vault"
import type { AuthPayload } from "@/api/gen/oblivio/v1/common_pb"

type MFAState = {
  sessionId: string
  totpRequired: boolean
  webauthnRequired: boolean
  webauthnOptions: PublicKeyCredentialRequestOptionsJSON | null
  // Cached so we can finalise unlock once tokens arrive.
  masterKey: CryptoKey
  masterKeyRaw: Uint8Array
}

export default function LoginPage() {
  const navigate = useNavigate()
  const setSession = useAuthStore((s) => s.setSession)
  const setVaultKey = useVaultStore((s) => s.setVaultKey)
  const deviceId = useAuthStore((s) => s.deviceId)

  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [totpCode, setTotpCode] = useState("")
  const [mfa, setMfa] = useState<MFAState | null>(null)

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
        p: Math.max(1, kdf.kdfParams.p),
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

      if (resp.authPayload) {
        await finishUnlock(masterKey, masterKeyRaw, resp.authPayload)
        return
      }
      if (!resp.mfaChallenge) throw new Error("invalid credentials")

      // MFA path. Cache the master key so we can complete the unlock once
      // CompleteMFA returns. The raw bytes hang around until then so we can
      // re-derive auth_key for the WebAuthn assertion path if needed.
      let opts: PublicKeyCredentialRequestOptionsJSON | null = null
      if (resp.mfaChallenge.webauthnOptionsJson && resp.mfaChallenge.webauthnOptionsJson.length > 0) {
        const decoded = JSON.parse(
          new TextDecoder().decode(resp.mfaChallenge.webauthnOptionsJson),
        ) as { publicKey: PublicKeyCredentialRequestOptionsJSON }
        opts = decoded.publicKey
      }

      setMfa({
        sessionId: resp.mfaChallenge.sessionId,
        totpRequired: resp.mfaChallenge.totpRequired,
        webauthnRequired: resp.mfaChallenge.webauthnRequired,
        webauthnOptions: opts,
        masterKey,
        masterKeyRaw,
      })
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  async function completeTOTP() {
    if (!mfa) return
    setBusy(true)
    setError(null)
    try {
      const resp = await authClient.completeMFA({
        sessionId: mfa.sessionId,
        totpCode,
        deviceInfo: {
          deviceId,
          deviceType: "web",
          deviceName: navigator.userAgent.slice(0, 64),
        },
      })
      if (!resp.authPayload) throw new Error("server returned no auth payload")
      await finishUnlock(mfa.masterKey, mfa.masterKeyRaw, resp.authPayload)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  async function completeWebAuthn() {
    if (!mfa || !mfa.webauthnOptions) return
    setBusy(true)
    setError(null)
    try {
      const assertion = await startAuthentication({ optionsJSON: mfa.webauthnOptions })
      const assertionBytes = new TextEncoder().encode(JSON.stringify(assertion))
      const resp = await authClient.completeMFA({
        sessionId: mfa.sessionId,
        webauthnAssertionJson: assertionBytes,
        deviceInfo: {
          deviceId,
          deviceType: "web",
          deviceName: navigator.userAgent.slice(0, 64),
        },
      })
      if (!resp.authPayload) throw new Error("server returned no auth payload")
      await finishUnlock(mfa.masterKey, mfa.masterKeyRaw, resp.authPayload)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  // finishUnlock decrypts vault_key from the AuthPayload, populates stores,
  // wipes plaintext key material and navigates into the app shell.
  async function finishUnlock(
    masterKey: CryptoKey,
    masterKeyRaw: Uint8Array,
    payload: AuthPayload,
  ) {
    if (!(await checkVerifier(masterKey, payload.verifier))) {
      throw new Error("verifier check failed — wrong password")
    }
    const vaultKey = await unwrapVaultKey(masterKey, payload.wrappedVaultKey)
    // Prime the session before GetMe so the Bearer interceptor finds a token.
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
    setMfa(null)
    setTotpCode("")
    setPassword("")
    navigate({ to: "/app" })
  }

  if (mfa) {
    return (
      <div className="space-y-4">
        <div className="space-y-2">
          <h1 className="text-2xl font-semibold">Second factor required</h1>
          <p className="text-sm text-muted-foreground">
            Confirm sign-in with your authenticator.
          </p>
        </div>
        {mfa.totpRequired && (
          <div className="space-y-2">
            <Input
              inputMode="numeric"
              placeholder="123 456"
              maxLength={10}
              autoFocus
              value={totpCode}
              onChange={(e) => setTotpCode(e.target.value)}
            />
            <Button
              className="w-full"
              onClick={completeTOTP}
              disabled={busy || !totpCode}
            >
              {busy ? "Verifying…" : "Verify code"}
            </Button>
          </div>
        )}
        {mfa.webauthnRequired && mfa.webauthnOptions && (
          <Button
            className="w-full"
            variant="outline"
            onClick={completeWebAuthn}
            disabled={busy}
          >
            {busy ? "Waiting for authenticator…" : "Use passkey"}
          </Button>
        )}
        {error && <p className="text-sm text-destructive">{error}</p>}
        <button
          type="button"
          className="text-center text-sm text-muted-foreground underline"
          onClick={() => {
            mfa.masterKeyRaw.fill(0)
            setMfa(null)
          }}
        >
          Cancel
        </button>
      </div>
    )
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
      <p className="text-center text-sm text-muted-foreground">
        Forgot your master password?{" "}
        <Link to="/recover" className="text-foreground underline">
          Use recovery code
        </Link>
      </p>
    </form>
  )
}

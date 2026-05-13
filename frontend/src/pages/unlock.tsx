// Unlock screen — re-derive vault_key from master_password without
// dropping the access token. We use the same KDF params returned by
// /authorize but skip the network call by reading GetMyKeys for the
// stored verifier + wrapped_vault_key.
//
// Optionally, when the user has enrolled at least one passkey for
// unlock (see settings · two-factor → "Use to unlock"), they can skip
// the password entirely: a server-bound WebAuthn assertion with the
// PRF extension produces the same key the password would, and the
// vault unwraps without ever seeing master_key.

import { useEffect, useState } from "react"
import { useNavigate } from "@tanstack/react-router"
import type { PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/browser"

import { authClient, vaultClient, webauthnClient } from "@/api/client"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useAuthStore } from "@/stores/auth"
import { useVaultStore } from "@/stores/vault"
import {
  assertionToJSON,
  bytesToBase64Url,
  readPrfFirst,
  requestOptionsFromJSON,
} from "@/lib/webauthn-json"
import {
  checkVerifier,
  derivePasskeyUnlockKey,
  deriveAuthKey,
  deriveMasterKey,
  importMasterKey,
  passkeyUnlockAAD,
  unwrapVaultKey,
  unwrapVaultKeyWithPRF,
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
  const [passkeyCount, setPasskeyCount] = useState<number | null>(null)

  // Probe ListCredentials once on mount to decide whether to surface the
  // "Unlock with passkey" button. The call is cheap and the result is
  // authenticated already (we have the access token).
  useEffect(() => {
    let cancelled = false
    void (async () => {
      try {
        const r = await webauthnClient.listCredentials({})
        if (cancelled) return
        const n = r.credentials.filter((c) => c.unlockEnabled).length
        setPasskeyCount(n)
      } catch {
        if (!cancelled) setPasskeyCount(0)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

  async function unlockWithPassword(e: React.FormEvent) {
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
      await deriveAuthKey(masterKeyRaw, kdf.saltUser)

      const keys = await authClient.getMyKeys({})
      if (!(await checkVerifier(masterKey, keys.verifier))) {
        throw new Error("wrong master password")
      }
      const vaultKey = await unwrapVaultKey(masterKey, keys.wrappedVaultKey)
      setVaultKey(vaultKey, keys.vaultKeyVersion, kdf.blindPepper)
      masterKeyRaw.fill(0)

      const me = await vaultClient.getMe({})
      useAuthStore.setState({ userId: me.userId, email: me.email })

      await navigate({ to: "/" })
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  async function unlockWithPasskey() {
    setError(null)
    if (!email) {
      setError("session expired — sign in again")
      return
    }
    setBusy(true)
    try {
      // The server seeds a real WebAuthn challenge bound to this
      // session and limits allowCredentials to the user's keys.
      const begin = await webauthnClient.beginAssertion({})
      const decoded = JSON.parse(
        new TextDecoder().decode(begin.optionsJson)
      ) as { publicKey: PublicKeyCredentialRequestOptionsJSON }

      // Each enabled credential was registered with its own prf_salt.
      // To make the authenticator return the right PRF output for
      // whichever key the user picks, build evalByCredential keyed by
      // the AUTHENTICATOR's raw credential id (base64url).
      const list = await webauthnClient.listCredentials({})
      const eligible = list.credentials.filter(
        (c) => c.unlockEnabled && c.rawCredentialId.length > 0
      )
      if (eligible.length === 0) {
        throw new Error("no passkey enrolled for unlock")
      }
      const evalByCredential: Record<
        string,
        { first: Uint8Array }
      > = {}
      for (const c of eligible) {
        evalByCredential[bytesToBase64Url(c.rawCredentialId)] = {
          first: c.prfSalt,
        }
      }

      // Use native navigator.credentials.get — @simplewebauthn/browser
      // 13.3 doesn't convert PRF eval inputs from base64url to
      // ArrayBuffer, so calling it with prf in extensions throws
      // "value is not of type '(ArrayBuffer or ArrayBufferView)'".
      const publicKey = requestOptionsFromJSON(decoded.publicKey, {
        eval: { first: eligible[0].prfSalt }, // fallback when ABC unsupported
        evalByCredential,
      })
      const cred = (await navigator.credentials.get({
        publicKey,
      })) as PublicKeyCredential | null
      if (!cred) {
        throw new Error("no credential was returned by the authenticator")
      }
      const prfOutput = readPrfFirst(cred)
      if (!prfOutput) {
        throw new Error(
          "this authenticator did not return a PRF result — try the master password"
        )
      }

      // Hand the assertion to the server for validation + blob
      // retrieval. The server uses the matched DB row's id to look up
      // the wrapped_vault_key and echoes that id back so we can
      // rebuild the wrap-time AAD.
      const assertionBytes = new TextEncoder().encode(
        JSON.stringify(assertionToJSON(cred))
      )
      const unlockResp = await webauthnClient.unlockWithPasskey({
        mfaSessionId: begin.sessionId,
        webauthnAssertionJson: assertionBytes,
      })
      if (!unlockResp.credentialId) {
        throw new Error("server did not return the matched credential id")
      }

      const unlockKey = await derivePasskeyUnlockKey(prfOutput)
      prfOutput.fill(0)

      const me = await vaultClient.getMe({})
      const vaultKey = await unwrapVaultKeyWithPRF(
        unlockKey,
        unlockResp.wrappedVaultKey,
        passkeyUnlockAAD(me.userId, unlockResp.credentialId)
      )

      const kdf = await authClient.getKDFParams({ email })
      const keys = await authClient.getMyKeys({})
      setVaultKey(vaultKey, keys.vaultKeyVersion, kdf.blindPepper)
      useAuthStore.setState({ userId: me.userId, email: me.email })

      await navigate({ to: "/" })
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

  const passkeyAvailable = (passkeyCount ?? 0) > 0

  return (
    <form onSubmit={unlockWithPassword} className="space-y-4">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold">Unlock vault</h1>
        <p className="text-sm text-muted-foreground">
          {email
            ? `Signed in as ${email}. Use your master password${
                passkeyAvailable ? " — or unlock with a passkey." : "."
              }`
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
      <div className="flex flex-wrap gap-2">
        <Button type="submit" className="flex-1" disabled={busy || !email}>
          {busy ? "Unlocking…" : "Unlock"}
        </Button>
        {passkeyAvailable && (
          <Button
            type="button"
            variant="outline"
            onClick={unlockWithPasskey}
            disabled={busy || !email}
          >
            Unlock with passkey
          </Button>
        )}
        <Button type="button" variant="ghost" onClick={handleSignOut}>
          Sign out
        </Button>
      </div>
    </form>
  )
}


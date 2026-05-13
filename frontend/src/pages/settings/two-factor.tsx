// Settings · Two-factor authentication.
//
// Lets the user enrol/disable a login-TOTP secret and register / remove
// WebAuthn passkeys. The TOTP secret is generated locally and encrypted
// under K_login_totp = HKDF(auth_key, "oblivio/login-totp/v1") before
// reaching the server — the server only stores the ciphertext.

import { useEffect, useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import QRCode from "qrcode"
import {
  startAuthentication,
  startRegistration,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser"

import {
  authClient,
  loginTotpClient,
  vaultClient,
  webauthnClient,
} from "@/api/client"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import {
  PRF_SALT_LENGTH,
  derivePasskeyUnlockKey,
  deriveAuthKey,
  deriveLoginTotpKey,
  deriveMasterKey,
  generatePrfSalt,
  generateTotpCode,
  generateTotpSecret,
  importMasterKey,
  otpauthURI,
  passkeyUnlockAAD,
  totpRemainingSeconds,
  wrapLoginTotpSecret,
  wrapVaultKeyWithPRF,
  type Argon2Params,
} from "@oblivio/crypto"

import { useAuthStore } from "@/stores/auth"
import { useVaultStore } from "@/stores/vault"
import { readPrfFirst } from "@/lib/webauthn-json"

const ISSUER = "Oblivio"

export default function TwoFactorPage() {
  const email = useAuthStore((s) => s.email) ?? ""
  const qc = useQueryClient()

  const meQ = useQuery({
    queryKey: ["vault", "me"],
    queryFn: async () => vaultClient.getMe({}),
  })
  const credsQ = useQuery({
    queryKey: ["webauthn", "list"],
    queryFn: async () => webauthnClient.listCredentials({}),
  })

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">
          Two-factor authentication
        </h1>
        <p className="text-sm text-muted-foreground">
          Add a TOTP code or passkey on top of your master password.
        </p>
      </header>

      <TotpSection
        email={email}
        enabled={meQ.data?.totpEnabled ?? false}
        onChanged={() => qc.invalidateQueries({ queryKey: ["vault", "me"] })}
      />

      <PasskeySection
        email={email}
        credentials={credsQ.data?.credentials ?? []}
        loading={credsQ.isLoading}
        onChanged={() => {
          qc.invalidateQueries({ queryKey: ["webauthn", "list"] })
          qc.invalidateQueries({ queryKey: ["vault", "me"] })
        }}
      />
    </div>
  )
}

// --- TOTP -------------------------------------------------------------

function TotpSection({
  email,
  enabled,
  onChanged,
}: {
  email: string
  enabled: boolean
  onChanged: () => void
}) {
  const [pending, setPending] = useState(false)
  const [secret, setSecret] = useState<string | null>(null)
  const [qr, setQr] = useState<string | null>(null)
  const [code, setCode] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [preview, setPreview] = useState<string>("------")
  const [remaining, setRemaining] = useState<number>(30)

  // Live-preview the code the user will see in their authenticator.
  useEffect(() => {
    if (!secret) return
    let cancelled = false
    async function tick() {
      const now = new Date()
      const c = await generateTotpCode(secret!, now)
      const rem = totpRemainingSeconds(now)
      if (!cancelled) {
        setPreview(c)
        setRemaining(rem)
      }
    }
    tick()
    const id = setInterval(tick, 1000)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [secret])

  async function begin() {
    setError(null)
    setSecret(null)
    setQr(null)
    const s = generateTotpSecret()
    const uri = otpauthURI({ issuer: ISSUER, account: email, secret: s })
    const dataUrl = await QRCode.toDataURL(uri)
    setSecret(s)
    setQr(dataUrl)
  }

  async function activate() {
    if (!secret) return
    setPending(true)
    setError(null)
    try {
      const { authKey } = await deriveAuthKeyFromPassword(email, password)
      const totpKey = await deriveLoginTotpKey(authKey)
      const wrapped = await wrapLoginTotpSecret(totpKey, secret)
      // nonce lives inside `wrapped` (first 12 bytes), but the schema asks
      // for it separately too — Sprint 4 may relocate it.
      const nonce = wrapped.slice(0, 12)
      await loginTotpClient.setup({
        encryptedSecret: wrapped,
        nonce,
        authKey,
        totpCode: code,
      })
      await loginTotpClient.enable({ authKey, totpCode: code })
      toast.success("TOTP enabled")
      setSecret(null)
      setQr(null)
      setCode("")
      setPassword("")
      onChanged()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setPending(false)
    }
  }

  async function disable() {
    setPending(true)
    setError(null)
    try {
      const { authKey } = await deriveAuthKeyFromPassword(email, password)
      await loginTotpClient.disable({ authKey, totpCode: code })
      toast.success("TOTP disabled")
      setCode("")
      setPassword("")
      onChanged()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setPending(false)
    }
  }

  // Disable TOTP via passkey: re-authenticates with WebAuthn instead of
  // requiring a fresh TOTP code (useful when the user lost their app).
  // Master password is still required so a stolen access token alone
  // can't downgrade 2FA.
  async function disableViaPasskey() {
    setPending(true)
    setError(null)
    try {
      const { authKey } = await deriveAuthKeyFromPassword(email, password)
      const begin = await webauthnClient.beginAssertion({})
      const optsObj = JSON.parse(
        new TextDecoder().decode(begin.optionsJson)
      ) as {
        publicKey: PublicKeyCredentialRequestOptionsJSON
      }
      const assertion = await startAuthentication({
        optionsJSON: optsObj.publicKey,
      })
      const assertionJson = new TextEncoder().encode(JSON.stringify(assertion))
      await loginTotpClient.disable({
        authKey,
        webauthnAssertionJson: assertionJson,
        mfaSessionId: begin.sessionId,
      })
      toast.success("TOTP disabled (via passkey)")
      setCode("")
      setPassword("")
      onChanged()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setPending(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          Authenticator app (TOTP)
          {enabled && <Badge>Enabled</Badge>}
        </CardTitle>
        <CardDescription>
          A 6-digit code generated by your authenticator app every 30 seconds.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {enabled ? (
          <>
            <p className="text-sm text-muted-foreground">
              Provide your current code and master password to remove the second
              factor.
            </p>
            <div className="grid grid-cols-2 gap-3">
              <Input
                type="password"
                placeholder="master password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              <Input
                inputMode="numeric"
                placeholder="123 456"
                maxLength={10}
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
            </div>
            {error && <p className="text-sm text-destructive">{error}</p>}
            <div className="flex flex-wrap gap-2">
              <Button
                onClick={disable}
                variant="destructive"
                disabled={pending}
              >
                {pending ? "Disabling…" : "Disable TOTP"}
              </Button>
              <Button
                onClick={disableViaPasskey}
                variant="outline"
                disabled={pending || !password}
                title="Use a registered passkey instead of a TOTP code"
              >
                Disable via passkey
              </Button>
            </div>
          </>
        ) : !secret ? (
          <Button onClick={begin}>Set up TOTP</Button>
        ) : (
          <div className="space-y-4">
            <div className="flex flex-col items-start gap-4 sm:flex-row sm:items-center">
              {qr && (
                <img
                  src={qr}
                  alt="otpauth QR"
                  className="size-40 rounded-md border bg-white p-2"
                />
              )}
              <div className="space-y-2 text-sm">
                <p className="text-muted-foreground">
                  Scan the QR or paste the secret manually:
                </p>
                <pre className="rounded border bg-muted p-2 font-mono text-xs break-all">
                  {secret}
                </pre>
                <p className="text-muted-foreground">
                  Next code: <span className="font-mono">{preview}</span>{" "}
                  <span className="text-xs">({remaining}s)</span>
                </p>
              </div>
            </div>
            <p className="text-sm">
              Enter your master password and the current code from your app to
              activate.
            </p>
            <div className="grid grid-cols-2 gap-3">
              <Input
                type="password"
                placeholder="master password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              <Input
                inputMode="numeric"
                placeholder="123 456"
                maxLength={10}
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
            </div>
            {error && <p className="text-sm text-destructive">{error}</p>}
            <div className="flex gap-2">
              <Button
                onClick={activate}
                disabled={pending || !code || !password}
              >
                {pending ? "Activating…" : "Activate"}
              </Button>
              <Button
                variant="ghost"
                onClick={() => {
                  setSecret(null)
                  setQr(null)
                }}
              >
                Cancel
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// --- WebAuthn ---------------------------------------------------------

// Per-credential metadata as returned by ListCredentials. The proto-
// generated type is a class; we narrow to the fields we actually consume.
type CredentialRow = {
  id: string
  name: string
  unlockEnabled: boolean
  prfSalt: Uint8Array
}

function PasskeySection({
  email,
  credentials,
  loading,
  onChanged,
}: {
  email: string
  credentials: CredentialRow[]
  loading: boolean
  onChanged: () => void
}) {
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [name, setName] = useState("")
  const [removePw, setRemovePw] = useState<{ id: string; pw: string } | null>(
    null
  )
  const [unlockPw, setUnlockPw] = useState<{ id: string; pw: string } | null>(
    null
  )

  const vaultKey = useVaultStore((s) => s.vaultKey)
  const userId = useAuthStore((s) => s.userId)

  const registerMut = useMutation({
    mutationFn: async () => {
      const begin = await webauthnClient.registerBegin({
        credentialName: name || "passkey",
      })
      const options = JSON.parse(
        new TextDecoder().decode(begin.optionsJson)
      ) as { publicKey: PublicKeyCredentialCreationOptionsJSON }
      const attestation = await startRegistration({
        optionsJSON: options.publicKey,
      })
      const attestationBytes = new TextEncoder().encode(
        JSON.stringify(attestation)
      )
      await webauthnClient.registerFinish({
        sessionId: begin.sessionId,
        attestationJson: attestationBytes,
      })
    },
    onSuccess: () => {
      toast.success("Passkey added")
      setName("")
      onChanged()
    },
    onError: (e) => setError(e instanceof Error ? e.message : String(e)),
    onSettled: () => setPending(false),
  })

  const removeMut = useMutation({
    mutationFn: async ({ id, password }: { id: string; password: string }) => {
      const { authKey } = await deriveAuthKeyFromPassword(email, password)
      await webauthnClient.removeCredential({ credentialId: id, authKey })
    },
    onSuccess: () => {
      toast.success("Passkey removed")
      setRemovePw(null)
      onChanged()
    },
    onError: (e) => toast.error(`Remove failed: ${(e as Error).message}`),
  })

  // Enable passkey unlock: perform an assertion ceremony with the PRF
  // extension to derive the unlock key, wrap vault_key, and upload.
  const enableUnlockMut = useMutation({
    mutationFn: async ({ id, password }: { id: string; password: string }) => {
      if (!vaultKey) {
        throw new Error("vault must be unlocked to enable passkey unlock")
      }
      if (!userId) {
        throw new Error("session missing user id")
      }
      const { authKey } = await deriveAuthKeyFromPassword(email, password)
      const salt = generatePrfSalt()
      const prfOutput = await assertWithPRF(id, salt)
      const unlockKey = await derivePasskeyUnlockKey(prfOutput)
      // Wipe the raw PRF output as soon as the AES key is imported.
      prfOutput.fill(0)
      const wrapped = await wrapVaultKeyWithPRF(
        unlockKey,
        vaultKey,
        passkeyUnlockAAD(userId, id)
      )
      await webauthnClient.enablePasskeyUnlock({
        credentialId: id,
        wrappedVaultKey: wrapped,
        prfSalt: salt,
        authKey,
      })
    },
    onSuccess: () => {
      toast.success("Passkey unlock enabled")
      setUnlockPw(null)
      onChanged()
    },
    onError: (e) => toast.error(`Enable failed: ${(e as Error).message}`),
  })

  const disableUnlockMut = useMutation({
    mutationFn: async ({ id, password }: { id: string; password: string }) => {
      const { authKey } = await deriveAuthKeyFromPassword(email, password)
      await webauthnClient.disablePasskeyUnlock({ credentialId: id, authKey })
    },
    onSuccess: () => {
      toast.success("Passkey unlock disabled")
      setUnlockPw(null)
      onChanged()
    },
    onError: (e) => toast.error(`Disable failed: ${(e as Error).message}`),
  })

  return (
    <Card>
      <CardHeader>
        <CardTitle>Passkeys</CardTitle>
        <CardDescription>
          Hardware keys, platform authenticators and synced passkeys (Touch ID,
          Windows Hello, YubiKey…). Phishing-resistant because the browser
          checks the origin before signing. Removing a passkey requires your
          master password.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          {loading && <p className="text-sm text-muted-foreground">Loading…</p>}
          {!loading && credentials.length === 0 && (
            <p className="text-sm text-muted-foreground">No passkeys yet.</p>
          )}
          {credentials.map((c) => {
            const removeOpen = removePw?.id === c.id
            const unlockOpen = unlockPw?.id === c.id
            return (
              <div
                key={c.id}
                className="space-y-2 rounded-md border bg-muted/30 px-3 py-2"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-medium">{c.name}</span>
                    {c.unlockEnabled && <Badge>Unlock enabled</Badge>}
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() =>
                        setUnlockPw(unlockOpen ? null : { id: c.id, pw: "" })
                      }
                    >
                      {c.unlockEnabled ? "Disable unlock" : "Use to unlock"}
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() =>
                        setRemovePw(removeOpen ? null : { id: c.id, pw: "" })
                      }
                    >
                      Remove
                    </Button>
                  </div>
                </div>
                {removeOpen && (
                  <InlinePasswordForm
                    label="Confirm with master password to remove this passkey"
                    busy={removeMut.isPending}
                    onCancel={() => setRemovePw(null)}
                    onSubmit={(password) =>
                      removeMut.mutate({ id: c.id, password })
                    }
                  />
                )}
                {unlockOpen && !c.unlockEnabled && (
                  <PasskeyUnlockEnableWarning />
                )}
                {unlockOpen && (
                  <InlinePasswordForm
                    label={
                      c.unlockEnabled
                        ? "Confirm with master password to disable passkey unlock"
                        : !vaultKey
                          ? "Vault must be unlocked first — return to the vault, then come back."
                          : "Confirm with master password. The browser will ask you to use the passkey to derive the unlock key."
                    }
                    busy={enableUnlockMut.isPending || disableUnlockMut.isPending}
                    disabled={!c.unlockEnabled && !vaultKey}
                    onCancel={() => setUnlockPw(null)}
                    onSubmit={(password) =>
                      c.unlockEnabled
                        ? disableUnlockMut.mutate({ id: c.id, password })
                        : enableUnlockMut.mutate({ id: c.id, password })
                    }
                  />
                )}
              </div>
            )
          })}
        </div>
        <div className="grid grid-cols-[1fr_auto] gap-2">
          <Input
            placeholder="Label (e.g. YubiKey 5)"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <Button
            onClick={() => {
              setPending(true)
              setError(null)
              registerMut.mutate()
            }}
            disabled={pending}
          >
            {pending ? "Registering…" : "Add passkey"}
          </Button>
        </div>
        {error && <p className="text-sm text-destructive">{error}</p>}
      </CardContent>
    </Card>
  )
}

// PasskeyUnlockEnableWarning is the explicit trade-off notice shown
// before the user enables passkey-as-vault-key for the first time on a
// credential. Until this point, vault_key was only reachable via the
// master password; once enabled, anyone who controls the passkey can
// unwrap vault_key. For synced passkeys (iCloud Keychain, Chrome Sync,
// password-manager-as-passkey) that effectively extends vault access
// to whoever can sign in to the provider account.
function PasskeyUnlockEnableWarning() {
  return (
    <div className="space-y-1 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-900 dark:text-amber-200">
      <p className="font-semibold">
        This grants vault access to the passkey’s owner.
      </p>
      <ul className="list-disc space-y-1 pl-4">
        <li>
          A synced passkey (iCloud Keychain, Chrome Sync, password manager)
          means anyone who takes over that account can decrypt your vault
          without your master password.
        </li>
        <li>
          A device-bound passkey (Touch ID, Windows Hello) means whoever
          can unlock that device with your biometrics or PIN can decrypt
          your vault.
        </li>
        <li>
          To revoke later: remove the passkey, or use
          “Also revoke passkey-unlock” on the Change-password form.
        </li>
      </ul>
    </div>
  )
}

// InlinePasswordForm is the reusable confirm-with-master-password row
// used by Remove / Enable-unlock / Disable-unlock.
function InlinePasswordForm({
  label,
  busy,
  disabled,
  onCancel,
  onSubmit,
}: {
  label: string
  busy: boolean
  disabled?: boolean
  onCancel: () => void
  onSubmit: (password: string) => void
}) {
  const [pw, setPw] = useState("")
  return (
    <div className="space-y-2">
      <p className="text-xs text-muted-foreground">{label}</p>
      <div className="grid grid-cols-[1fr_auto_auto] gap-2">
        <Input
          type="password"
          placeholder="master password"
          autoComplete="current-password"
          value={pw}
          onChange={(e) => setPw(e.target.value)}
          disabled={disabled}
        />
        <Button
          size="sm"
          onClick={() => onSubmit(pw)}
          disabled={busy || disabled || !pw}
        >
          {busy ? "Working…" : "Confirm"}
        </Button>
        <Button size="sm" variant="ghost" onClick={onCancel} disabled={busy}>
          Cancel
        </Button>
      </div>
    </div>
  )
}

// assertWithPRF performs a one-shot WebAuthn assertion with the PRF
// extension and returns the 32-byte PRF output (HMAC-SHA-256 of the
// salt under the authenticator's PRF key). The challenge is
// client-generated because we are NOT authenticating to the server
// here — we just want the PRF result. The server-validated unlock
// path (UnlockWithPasskey) uses BeginAssertion to seed a real,
// server-bound challenge.
//
// We call the native API directly: @simplewebauthn/browser 13.3
// passes `extensions.prf.eval.first` through verbatim, so a
// base64url-encoded string lands in `navigator.credentials.get` and
// the browser rejects it with a TypeError. Constructing the request
// natively lets us hand `eval.first` an ArrayBuffer.
async function assertWithPRF(
  credentialId: string,
  salt: Uint8Array
): Promise<Uint8Array> {
  if (salt.length !== PRF_SALT_LENGTH) {
    throw new Error(`prf salt must be ${PRF_SALT_LENGTH} bytes`)
  }
  const challenge = new Uint8Array(32)
  crypto.getRandomValues(challenge)
  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: challenge.buffer as ArrayBuffer,
    timeout: 60_000,
    userVerification: "required",
    extensions: {
      // TypeScript's lib.dom.d.ts doesn't always include `prf` in
      // AuthenticationExtensionsClientInputs — cast at the boundary.
      prf: {
        eval: { first: salt.buffer as ArrayBuffer },
      },
    } as unknown as AuthenticationExtensionsClientInputs,
  }
  const cred = (await navigator.credentials.get({
    publicKey,
  })) as PublicKeyCredential | null
  if (!cred) {
    throw new Error("no credential was returned by the authenticator")
  }
  // `credentialId` is the server-side row UUID; cred.id is the
  // authenticator's base64url-encoded raw credential id, so the two
  // can't be string-compared. We just trust the user picked the right
  // passkey — Enable always calls back into the server with this id
  // attached, and the server validates ownership before storing.
  void credentialId
  const prfOutput = readPrfFirst(cred)
  if (!prfOutput) {
    throw new Error(
      "this authenticator does not support the PRF extension; unlock via passkey is unavailable"
    )
  }
  return prfOutput
}

// --- shared helper ----------------------------------------------------

// deriveAuthKeyFromPassword fetches the user's KDF params and re-runs the
// password-derivation pipeline to produce a fresh auth_key. The master_key
// raw bytes are wiped before returning so this helper is safe to use in
// settings forms where the password is collected just-in-time.
async function deriveAuthKeyFromPassword(
  email: string,
  password: string
): Promise<{ authKey: Uint8Array }> {
  if (!email || !password) {
    throw new Error("email and master password required")
  }
  const kdf = await authClient.getKDFParams({ email })
  if (!kdf.kdfParams) throw new Error("kdf params missing")
  const params: Argon2Params = {
    t: kdf.kdfParams.t,
    mKib: kdf.kdfParams.mKib,
    p: Math.max(1, kdf.kdfParams.p),
    algo: kdf.kdfParams.algo,
  }
  const masterKeyRaw = await deriveMasterKey(password, kdf.saltUser, params)
  // We don't need the CryptoKey here, but importing it consumes the bytes
  // safely. Skip if unused.
  try {
    await importMasterKey(masterKeyRaw)
  } catch {
    /* ignore */
  }
  const authKey = await deriveAuthKey(masterKeyRaw, kdf.saltUser)
  masterKeyRaw.fill(0)
  return { authKey }
}

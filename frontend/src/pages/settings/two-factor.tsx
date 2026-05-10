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
  startRegistration,
  type PublicKeyCredentialCreationOptionsJSON,
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
  deriveAuthKey,
  deriveLoginTotpKey,
  deriveMasterKey,
  generateTotpCode,
  generateTotpSecret,
  importMasterKey,
  otpauthURI,
  totpRemainingSeconds,
  wrapLoginTotpSecret,
  type Argon2Params,
} from "@oblivio/crypto"

import { useAuthStore } from "@/stores/auth"

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
        <h1 className="text-2xl font-semibold tracking-tight">Two-factor authentication</h1>
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
              Provide your current code and master password to remove the second factor.
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
            <Button onClick={disable} variant="destructive" disabled={pending}>
              {pending ? "Disabling…" : "Disable TOTP"}
            </Button>
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
              <Button onClick={activate} disabled={pending || !code || !password}>
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

function PasskeySection({
  credentials,
  loading,
  onChanged,
}: {
  credentials: { id: string; name: string }[]
  loading: boolean
  onChanged: () => void
}) {
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [name, setName] = useState("")

  const registerMut = useMutation({
    mutationFn: async () => {
      const begin = await webauthnClient.registerBegin({
        credentialName: name || "passkey",
      })
      const options = JSON.parse(
        new TextDecoder().decode(begin.optionsJson),
      ) as { publicKey: PublicKeyCredentialCreationOptionsJSON }
      const attestation = await startRegistration({
        optionsJSON: options.publicKey,
      })
      const attestationBytes = new TextEncoder().encode(
        JSON.stringify(attestation),
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
    mutationFn: async (id: string) =>
      webauthnClient.removeCredential({ credentialId: id }),
    onSuccess: () => {
      toast.success("Passkey removed")
      onChanged()
    },
    onError: (e) =>
      toast.error(`Remove failed: ${(e as Error).message}`),
  })

  return (
    <Card>
      <CardHeader>
        <CardTitle>Passkeys</CardTitle>
        <CardDescription>
          Hardware keys, platform authenticators and synced passkeys (Touch ID,
          Windows Hello, YubiKey…). Phishing-resistant because the browser
          checks the origin before signing.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          {loading && (
            <p className="text-sm text-muted-foreground">Loading…</p>
          )}
          {!loading && credentials.length === 0 && (
            <p className="text-sm text-muted-foreground">No passkeys yet.</p>
          )}
          {credentials.map((c) => (
            <div
              key={c.id}
              className="flex items-center justify-between rounded-md border bg-muted/30 px-3 py-2"
            >
              <span className="font-medium">{c.name}</span>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => removeMut.mutate(c.id)}
                disabled={removeMut.isPending}
              >
                Remove
              </Button>
            </div>
          ))}
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

// --- shared helper ----------------------------------------------------

// deriveAuthKeyFromPassword fetches the user's KDF params and re-runs the
// password-derivation pipeline to produce a fresh auth_key. The master_key
// raw bytes are wiped before returning so this helper is safe to use in
// settings forms where the password is collected just-in-time.
async function deriveAuthKeyFromPassword(
  email: string,
  password: string,
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
  const authKey = await deriveAuthKey(masterKeyRaw, email)
  masterKeyRaw.fill(0)
  return { authKey }
}

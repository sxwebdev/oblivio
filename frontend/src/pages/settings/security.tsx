// Settings · Security.
//
// Cards:
//   1. Email verification — current status + Resend button.
//   2. Change master password — re-derive keys, rewrap vault_key.
//   3. Active sessions — list and remote-terminate any device.
//   4. Danger zone — DeleteMe (crypto-shred).
//
// All mutations attach a fresh Idempotency-Key so a double-click never
// duplicates a side-effect.

import { useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useNavigate } from "@tanstack/react-router"
import { toast } from "sonner"
import { Lock, Mail, ShieldAlert, Trash2 } from "lucide-react"
import {
  startAuthentication,
  type PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser"
import {
  deriveAuthKey,
  deriveLoginTotpKey,
  deriveMasterKey,
  importMasterKey,
  makeVerifier,
  pickArgon2Params,
  randomBytes,
  unwrapLoginTotpSecret,
  wrapLoginTotpSecret,
  wrapVaultKey,
  type Argon2Params,
} from "@oblivio/crypto"

import {
  authClient,
  idempotencyHeaders,
  sessionsClient,
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import type { Session } from "@/api/gen/oblivio/v1/sessions_pb"
import { useAuthStore } from "@/stores/auth"
import { useVaultStore } from "@/stores/vault"

export default function SecurityPage() {
  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Security</h1>
        <p className="text-sm text-muted-foreground">
          Manage where you are signed in and delete your account.
        </p>
      </header>
      <EmailVerificationCard />
      <ChangePasswordCard />
      <SessionsCard />
      <DangerCard />
    </div>
  )
}

// ---- Email verification ----------------------------------------------

function EmailVerificationCard() {
  const meQ = useQuery({
    queryKey: ["vault", "me"],
    queryFn: () => vaultClient.getMe({}),
  })
  const email = useAuthStore((s) => s.email) ?? ""
  const resend = useMutation({
    mutationFn: () => authClient.resendVerification({ email }),
    onSuccess: () =>
      toast.success("If your email is registered, a fresh link is on the way"),
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Resend failed"),
  })
  const verified = meQ.data?.emailVerified === true
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <div>
          <CardTitle className="flex items-center gap-2">
            <Mail className="size-5 text-primary" />
            Email verification
          </CardTitle>
          <CardDescription>
            Verifying your email lets us send recovery alerts and security
            notifications.
          </CardDescription>
        </div>
        <Badge variant={verified ? "default" : "secondary"}>
          {meQ.isLoading ? "…" : verified ? "Verified" : "Unverified"}
        </Badge>
      </CardHeader>
      <CardContent>
        {!verified && (
          <Button
            variant="outline"
            disabled={resend.isPending || !email}
            onClick={() => resend.mutate()}
          >
            {resend.isPending ? "Sending…" : "Resend verification email"}
          </Button>
        )}
      </CardContent>
    </Card>
  )
}

// ---- Change master password ------------------------------------------
//
// KDF is device-aware via pickArgon2Params (plan §17.2). The chosen profile
// at change-password time may differ from registration time if the user
// switches devices between registrations — the server stores whatever the
// client supplied in `new_kdf_params`.

function ChangePasswordCard() {
  const email = useAuthStore((s) => s.email) ?? ""
  const vaultKey = useVaultStore((s) => s.vaultKey)

  const [oldPwd, setOldPwd] = useState("")
  const [newPwd, setNewPwd] = useState("")
  const [confirmPwd, setConfirmPwd] = useState("")
  const [busy, setBusy] = useState(false)
  const [revokeUnlocks, setRevokeUnlocks] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!vaultKey) {
      toast.error("Vault locked — unlock first")
      return
    }
    if (newPwd.length < 8) {
      toast.error("New password must be at least 8 characters")
      return
    }
    if (newPwd !== confirmPwd) {
      toast.error("New password does not match the confirmation")
      return
    }
    setBusy(true)
    let oldMasterKeyRaw: Uint8Array | null = null
    let newMasterKeyRaw: Uint8Array | null = null
    try {
      // Re-derive the old auth_key under the user's CURRENT KDF params so
      // the server can verify possession of the old password.
      const params = await authClient.getKDFParams({ email })
      const oldKdf = params.kdfParams!
      oldMasterKeyRaw = await deriveMasterKey(oldPwd, params.saltUser, {
        t: oldKdf.t,
        mKib: oldKdf.mKib,
        p: oldKdf.p,
      })
      const oldAuthKey = await deriveAuthKey(oldMasterKeyRaw, params.saltUser)

      // Derive the new master_key, re-wrap the vault_key under it.
      const newSalt = randomBytes(16)
      const newKdf = pickArgon2Params()
      newMasterKeyRaw = await deriveMasterKey(newPwd, newSalt, newKdf)
      const newMasterKey = await importMasterKey(newMasterKeyRaw)
      const newAuthKey = await deriveAuthKey(newMasterKeyRaw, newSalt)
      const newWrappedVaultKey = await wrapVaultKey(newMasterKey, vaultKey)
      const newVerifier = await makeVerifier(newMasterKey)

      // If the user has login-TOTP configured, decrypt the old envelope
      // with the OLD K_login_totp and re-encrypt with the NEW one. Without
      // this round-trip the server's stored secret would become unreadable
      // (encrypted under the no-longer-derivable old auth_key).
      let newLoginTotpSecret = new Uint8Array(0)
      let newLoginTotpNonce = new Uint8Array(0)
      const existingKeys = await authClient.getMyKeys({})
      if (
        existingKeys.loginTotpEncryptedSecret &&
        existingKeys.loginTotpEncryptedSecret.length > 0
      ) {
        const oldTotpKey = await deriveLoginTotpKey(oldAuthKey)
        const plain = await unwrapLoginTotpSecret(
          oldTotpKey,
          existingKeys.loginTotpEncryptedSecret
        )
        const newTotpKey = await deriveLoginTotpKey(newAuthKey)
        const sealed = await wrapLoginTotpSecret(newTotpKey, plain)
        // Copy into a fresh Uint8Array so the generated proto setter,
        // which is typed Uint8Array<ArrayBuffer>, accepts the value.
        newLoginTotpSecret = new Uint8Array(sealed)
        // wrapLoginTotpSecret returns version|nonce|ct+tag; the server
        // stores it as a single column so nonce field is redundant but
        // proto requires it — emit a 1-byte placeholder. The server
        // treats either an empty encrypted_secret OR empty nonce as
        // "no envelope supplied"; supplying 1 byte passes the
        // len(...) > 0 check on both fields.
        newLoginTotpNonce = new Uint8Array([0])
      }

      await authClient.changeMasterPassword(
        {
          oldAuthKey,
          newAuthKey,
          newSaltUser: newSalt,
          newKdfParams: {
            t: newKdf.t,
            mKib: newKdf.mKib,
            p: newKdf.p,
            algo: newKdf.algo,
          },
          newVerifier,
          newWrappedVaultKey,
          newLoginTotpEncryptedSecret: newLoginTotpSecret,
          newLoginTotpNonce: newLoginTotpNonce,
          revokePasskeyUnlocks: revokeUnlocks,
        },
        { headers: idempotencyHeaders() }
      )
      toast.success(
        revokeUnlocks
          ? "Master password changed. Passkey-unlock revoked on all keys; other sessions signed out."
          : "Master password changed. Other sessions have been signed out."
      )
      setOldPwd("")
      setNewPwd("")
      setConfirmPwd("")
      setRevokeUnlocks(false)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Change failed")
    } finally {
      if (oldMasterKeyRaw) oldMasterKeyRaw.fill(0)
      if (newMasterKeyRaw) newMasterKeyRaw.fill(0)
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Lock className="size-5 text-primary" />
          Change master password
        </CardTitle>
        <CardDescription>
          Items themselves are not re-encrypted — only the wrapper around your
          vault key. All other sessions are signed out.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} className="space-y-3">
          <div>
            <Label htmlFor="cmp-old">Current password</Label>
            <Input
              id="cmp-old"
              type="password"
              autoComplete="current-password"
              value={oldPwd}
              onChange={(e) => setOldPwd(e.target.value)}
              required
            />
          </div>
          <div>
            <Label htmlFor="cmp-new">New password</Label>
            <Input
              id="cmp-new"
              type="password"
              autoComplete="new-password"
              value={newPwd}
              onChange={(e) => setNewPwd(e.target.value)}
              required
            />
          </div>
          <div>
            <Label htmlFor="cmp-confirm">Confirm new password</Label>
            <Input
              id="cmp-confirm"
              type="password"
              autoComplete="new-password"
              value={confirmPwd}
              onChange={(e) => setConfirmPwd(e.target.value)}
              required
            />
          </div>
          {/* vault_key is NOT rotated by a password change — only its
              master-key wrapper is. Passkey-unlock bundles wrap the same
              vault_key under a PRF-derived key, so they keep working
              after a rotation. Tick this when the rotation is driven by
              a suspected compromise (lost device, stolen credentials),
              so previously-leaked PRF outputs can no longer unlock. */}
          <label className="flex items-start gap-2 rounded-md border border-dashed border-muted-foreground/30 p-2 text-sm">
            <input
              type="checkbox"
              className="mt-0.5"
              checked={revokeUnlocks}
              onChange={(e) => setRevokeUnlocks(e.target.checked)}
            />
            <span>
              <strong>Also revoke passkey-unlock</strong> for all enrolled
              keys. Recommended if you suspect compromise — the credentials
              themselves remain registered, but they can no longer skip the
              master password on the unlock screen.
            </span>
          </label>
          <Button type="submit" disabled={busy || !vaultKey}>
            {busy ? "Changing…" : "Change password"}
          </Button>
        </form>
      </CardContent>
    </Card>
  )
}

// ---- Active sessions -------------------------------------------------

function SessionsCard() {
  const qc = useQueryClient()
  const listQ = useQuery({
    queryKey: ["sessions", "list"],
    queryFn: () => sessionsClient.listSessions({}),
  })

  const terminate = useMutation({
    mutationFn: async (sessionId: string) =>
      sessionsClient.terminateSession(
        { sessionId },
        { headers: idempotencyHeaders() }
      ),
    onSuccess: () => {
      toast.success("Session terminated")
      qc.invalidateQueries({ queryKey: ["sessions", "list"] })
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Termination failed"),
  })

  const terminateAll = useMutation({
    mutationFn: async () =>
      sessionsClient.terminateAllExceptCurrent(
        {},
        { headers: idempotencyHeaders() }
      ),
    onSuccess: (r) => {
      toast.success(
        `Terminated ${r.terminatedCount} other session${
          r.terminatedCount === 1 ? "" : "s"
        }`
      )
      qc.invalidateQueries({ queryKey: ["sessions", "list"] })
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Bulk termination failed"),
  })

  const sessions = listQ.data?.sessions ?? []
  const otherCount = sessions.filter((s) => !s.isCurrent).length

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <div>
          <CardTitle className="flex items-center gap-2">
            <Lock className="size-5 text-primary" />
            Active sessions
          </CardTitle>
          <CardDescription>
            Anyone signed in to your vault appears here. Terminating revokes the
            matching access &amp; refresh token immediately.
          </CardDescription>
        </div>
        <Button
          variant="outline"
          size="sm"
          disabled={otherCount === 0 || terminateAll.isPending}
          onClick={() => terminateAll.mutate()}
        >
          Sign out all others
        </Button>
      </CardHeader>
      <CardContent className="p-0">
        {listQ.isLoading && (
          <p className="py-6 text-center text-sm text-muted-foreground">
            Loading…
          </p>
        )}
        {!listQ.isLoading && sessions.length === 0 && (
          <p className="py-6 text-center text-sm text-muted-foreground">
            No active sessions.
          </p>
        )}
        {sessions.length > 0 && (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Device</TableHead>
                <TableHead>IP</TableHead>
                <TableHead>Last seen</TableHead>
                <TableHead className="text-right">Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sessions.map((s) => (
                <SessionRow
                  key={s.id}
                  session={s}
                  onTerminate={() => terminate.mutate(s.id)}
                  busy={terminate.isPending}
                />
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  )
}

function SessionRow({
  session,
  onTerminate,
  busy,
}: {
  session: Session
  onTerminate: () => void
  busy: boolean
}) {
  const label = session.deviceName || session.deviceType || session.deviceId
  return (
    <TableRow>
      <TableCell>
        <div className="flex items-center gap-2">
          <span className="font-medium">{label}</span>
          {session.isCurrent && <Badge variant="secondary">This device</Badge>}
        </div>
        <div className="text-xs text-muted-foreground">
          {session.deviceType}
        </div>
      </TableCell>
      <TableCell className="text-xs">
        {session.ip ?? "—"}
        {session.country ? ` · ${session.country}` : ""}
      </TableCell>
      <TableCell className="text-xs">
        {session.lastSeenAt
          ? new Date(Number(session.lastSeenAt.seconds) * 1000).toLocaleString()
          : "—"}
      </TableCell>
      <TableCell className="text-right">
        <Button
          variant="ghost"
          size="sm"
          disabled={busy || session.isCurrent}
          onClick={onTerminate}
        >
          Terminate
        </Button>
      </TableCell>
    </TableRow>
  )
}

// ---- Danger zone -----------------------------------------------------

function DangerCard() {
  return (
    <Card className="border-destructive/50">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-destructive">
          <ShieldAlert className="size-5" />
          Danger zone
        </CardTitle>
        <CardDescription>
          Permanently delete your account. All projects, items and the encrypted
          vault key are removed; any surviving backups become unreadable.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <DeleteAccountDialog />
      </CardContent>
    </Card>
  )
}

function DeleteAccountDialog() {
  const navigate = useNavigate()
  const clearSession = useAuthStore((s) => s.clear)
  const lockVault = useVaultStore((s) => s.lock)
  const email = useAuthStore((s) => s.email) ?? ""

  // The required factor set is derived from GetMe — we only ask for what
  // the server will require. A user without TOTP / passkey just types
  // their master password.
  const meQ = useQuery({
    queryKey: ["vault", "me"],
    queryFn: () => vaultClient.getMe({}),
  })
  const needsTotp = meQ.data?.totpEnabled === true
  const needsPasskey = (meQ.data?.webauthnCredentialsCount ?? 0) > 0

  const [open, setOpen] = useState(false)
  const [confirm, setConfirm] = useState("")
  const [reason, setReason] = useState("")
  const [password, setPassword] = useState("")
  const [totpCode, setTotpCode] = useState("")
  const [busy, setBusy] = useState(false)

  const canDelete =
    confirm.trim().toLowerCase() === email.toLowerCase() &&
    password.length > 0 &&
    (!needsTotp || totpCode.length > 0)

  async function submit() {
    setBusy(true)
    try {
      // 1) Re-derive auth_key from the just-typed master password.
      const kdf = await authClient.getKDFParams({ email })
      if (!kdf.kdfParams) throw new Error("kdf params missing")
      const params: Argon2Params = {
        t: kdf.kdfParams.t,
        mKib: kdf.kdfParams.mKib,
        p: Math.max(1, kdf.kdfParams.p),
        algo: kdf.kdfParams.algo,
      }
      const masterKeyRaw = await deriveMasterKey(password, kdf.saltUser, params)
      try {
        await importMasterKey(masterKeyRaw)
      } catch {
        /* ignore */
      }
      const authKey = await deriveAuthKey(masterKeyRaw, kdf.saltUser)
      masterKeyRaw.fill(0)

      // 2) Optional passkey assertion — seeded server-side so the server
      //    can validate it against the same challenge.
      let webauthnAssertionJson: Uint8Array | undefined
      let mfaSessionId: string | undefined
      if (needsPasskey) {
        const begin = await webauthnClient.beginAssertion({})
        const decoded = JSON.parse(
          new TextDecoder().decode(begin.optionsJson)
        ) as { publicKey: PublicKeyCredentialRequestOptionsJSON }
        const assertion = await startAuthentication({
          optionsJSON: decoded.publicKey,
        })
        webauthnAssertionJson = new TextEncoder().encode(
          JSON.stringify(assertion)
        )
        mfaSessionId = begin.sessionId
      }

      // 3) Submit the request — the server runs every factor before
      //    touching any data and only appends the audit row on success.
      await vaultClient.deleteMe(
        {
          reason,
          authKey,
          totpCode: needsTotp ? totpCode : "",
          webauthnAssertionJson: webauthnAssertionJson ?? new Uint8Array(0),
          mfaSessionId: mfaSessionId ?? "",
        },
        { headers: idempotencyHeaders() }
      )
      toast.success("Account deleted")
      lockVault()
      clearSession()
      setOpen(false)
      await navigate({ to: "/login" })
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Delete failed")
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Button variant="destructive" onClick={() => setOpen(true)}>
        <Trash2 className="size-4" />
        Delete account
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete account?</DialogTitle>
            <DialogDescription>
              This cannot be undone. The server immediately drops your vault key
              and removes every row that references your account.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div>
              <Label htmlFor="confirm-email">
                Type your email <span className="font-mono">{email}</span> to
                confirm
              </Label>
              <Input
                id="confirm-email"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                autoComplete="off"
              />
            </div>
            <div>
              <Label htmlFor="delete-password">Master password</Label>
              <Input
                id="delete-password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            {needsTotp && (
              <div>
                <Label htmlFor="delete-totp">Authenticator code</Label>
                <Input
                  id="delete-totp"
                  inputMode="numeric"
                  placeholder="123 456"
                  maxLength={10}
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value)}
                />
              </div>
            )}
            {needsPasskey && (
              <p className="text-xs text-muted-foreground">
                After confirming, your browser will prompt you to use one of
                your registered passkeys.
              </p>
            )}
            <div>
              <Label htmlFor="reason">
                Reason (optional, stored in audit log)
              </Label>
              <Input
                id="reason"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="e.g. switching service"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={!canDelete || busy}
              onClick={submit}
            >
              {busy ? "Deleting…" : "Delete forever"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}

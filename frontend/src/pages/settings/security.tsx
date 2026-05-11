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
  deriveAuthKey,
  deriveMasterKey,
  importMasterKey,
  makeVerifier,
  randomBytes,
  wrapVaultKey,
} from "@oblivio/crypto"

import {
  authClient,
  idempotencyHeaders,
  sessionsClient,
  vaultClient,
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

const KDF = { t: 3, mKib: 131072, p: 1, algo: "argon2id" } as const

function ChangePasswordCard() {
  const email = useAuthStore((s) => s.email) ?? ""
  const vaultKey = useVaultStore((s) => s.vaultKey)

  const [oldPwd, setOldPwd] = useState("")
  const [newPwd, setNewPwd] = useState("")
  const [confirmPwd, setConfirmPwd] = useState("")
  const [busy, setBusy] = useState(false)

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
      newMasterKeyRaw = await deriveMasterKey(newPwd, newSalt, KDF)
      const newMasterKey = await importMasterKey(newMasterKeyRaw)
      const newAuthKey = await deriveAuthKey(newMasterKeyRaw, newSalt)
      const newWrappedVaultKey = await wrapVaultKey(newMasterKey, vaultKey)
      const newVerifier = await makeVerifier(newMasterKey)

      await authClient.changeMasterPassword(
        {
          oldAuthKey,
          newAuthKey,
          newSaltUser: newSalt,
          newKdfParams: {
            t: KDF.t,
            mKib: KDF.mKib,
            p: KDF.p,
            algo: KDF.algo,
          },
          newVerifier,
          newWrappedVaultKey,
        },
        { headers: idempotencyHeaders() }
      )
      toast.success(
        "Master password changed. Other sessions have been signed out."
      )
      setOldPwd("")
      setNewPwd("")
      setConfirmPwd("")
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

  const [open, setOpen] = useState(false)
  const [confirm, setConfirm] = useState("")
  const [reason, setReason] = useState("")

  const deleteMe = useMutation({
    mutationFn: async () =>
      vaultClient.deleteMe({ reason }, { headers: idempotencyHeaders() }),
    onSuccess: async () => {
      toast.success("Account deleted")
      lockVault()
      clearSession()
      setOpen(false)
      await navigate({ to: "/login" })
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Delete failed"),
  })

  const canDelete = confirm.trim().toLowerCase() === email.toLowerCase()

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
              disabled={!canDelete || deleteMe.isPending}
              onClick={() => deleteMe.mutate()}
            >
              {deleteMe.isPending ? "Deleting…" : "Delete forever"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}

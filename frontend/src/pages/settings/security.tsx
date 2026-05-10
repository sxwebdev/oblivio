// Settings · Security.
//
// Two cards live here:
//   1. Active sessions — list and remote-terminate any device. The current
//      session is flagged so the user can see "this is me".
//   2. Danger zone — DeleteMe (crypto-shred). Triggers a confirm dialog
//      with explicit text typing (mistake-proofing).
//
// All mutations attach a fresh Idempotency-Key so a double-click never
// duplicates a side-effect.

import { useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useNavigate } from "@tanstack/react-router"
import { toast } from "sonner"
import { Lock, ShieldAlert, Trash2 } from "lucide-react"

import { idempotencyHeaders, sessionsClient, vaultClient } from "@/api/client"
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
      <SessionsCard />
      <DangerCard />
    </div>
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
        { headers: idempotencyHeaders() },
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
        { headers: idempotencyHeaders() },
      ),
    onSuccess: (r) => {
      toast.success(
        `Terminated ${r.terminatedCount} other session${
          r.terminatedCount === 1 ? "" : "s"
        }`,
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
            Anyone signed in to your vault appears here. Terminating revokes
            the matching access &amp; refresh token immediately.
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
        <div className="text-xs text-muted-foreground">{session.deviceType}</div>
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
          Permanently delete your account. All projects, items and the
          encrypted vault key are removed; any surviving backups become
          unreadable.
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
      vaultClient.deleteMe(
        { reason },
        { headers: idempotencyHeaders() },
      ),
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
            <Label htmlFor="reason">Reason (optional, stored in audit log)</Label>
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

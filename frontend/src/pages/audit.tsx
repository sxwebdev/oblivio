// Audit log viewer. The chain hashes are visible so the user can verify
// integrity off-line if they wish.

import { useQuery } from "@tanstack/react-query"

import { auditClient } from "@/api/client"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { AuditAction } from "@/api/gen/oblivio/v1/audit_pb"

const ACTION_LABELS: Record<number, string> = {
  [AuditAction.REGISTER]: "Register",
  [AuditAction.LOGIN]: "Login",
  [AuditAction.LOGOUT]: "Logout",
  [AuditAction.REFRESH]: "Refresh",
  [AuditAction.PASSWORD_CHANGE]: "Password change",
  [AuditAction.RECOVERY_START]: "Recovery start",
  [AuditAction.RECOVERY_COMPLETE]: "Recovery complete",
  [AuditAction.WEBAUTHN_REGISTER]: "WebAuthn register",
  [AuditAction.WEBAUTHN_REMOVE]: "WebAuthn remove",
  [AuditAction.TOTP_ENABLE]: "TOTP enable",
  [AuditAction.TOTP_DISABLE]: "TOTP disable",
  [AuditAction.PROJECT_CREATE]: "Project create",
  [AuditAction.PROJECT_UPDATE]: "Project update",
  [AuditAction.PROJECT_DELETE]: "Project delete",
  [AuditAction.ENTRY_CREATE]: "Entry create",
  [AuditAction.ENTRY_UPDATE]: "Entry update",
  [AuditAction.ENTRY_VIEW]: "Entry view",
  [AuditAction.ENTRY_DELETE]: "Entry delete",
  [AuditAction.SESSION_TERMINATE]: "Session terminate",
}

export default function AuditPage() {
  const listQ = useQuery({
    queryKey: ["audit"],
    queryFn: () => auditClient.listAudit({ limit: 100 }),
  })

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Audit log</h1>
        <p className="text-sm text-muted-foreground">
          A hash-chained record of every mutation on your vault. Verify-job
          alarms on tampering (Sprint 4).
        </p>
      </header>

      <Card>
        <CardHeader>
          <CardTitle>Latest events</CardTitle>
          <CardDescription>Newest first, up to 100 entries.</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {listQ.isLoading && (
            <p className="py-6 text-center text-sm text-muted-foreground">
              Loading…
            </p>
          )}
          {!listQ.isLoading && listQ.data?.entries.length === 0 && (
            <p className="py-6 text-center text-sm text-muted-foreground">
              No audit entries yet.
            </p>
          )}
          {!!listQ.data?.entries.length && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>When</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Self-hash (head)</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {listQ.data.entries.map((e) => (
                  <TableRow key={e.id.toString()}>
                    <TableCell className="font-mono text-xs">
                      {e.createdAt
                        ? new Date(
                            Number(e.createdAt.seconds) * 1000,
                          ).toLocaleString()
                        : "—"}
                    </TableCell>
                    <TableCell>
                      {ACTION_LABELS[e.action] ?? "Unknown"}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {e.targetId ?? "—"}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {bytesToShortHex(e.selfHash)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

function bytesToShortHex(b: Uint8Array): string {
  if (!b || b.length === 0) return "—"
  const head = Array.from(b.slice(0, 4))
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("")
  return `${head}…`
}

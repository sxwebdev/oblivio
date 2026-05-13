// Entry detail view. Decrypts the blob on demand and renders kind-specific
// sections. Copy-to-clipboard auto-clears via lib/clipboard.

import { useState } from "react"
import { Link, useNavigate } from "@tanstack/react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Copy, ExternalLink, Eye, EyeOff, Pencil, Trash2 } from "lucide-react"
import { toast } from "sonner"

import { entriesClient, idempotencyHeaders } from "@/api/client"
import { Badge } from "@/components/ui/badge"
import { Button, buttonVariants } from "@/components/ui/button"
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
import { EntryKind } from "@/api/gen/oblivio/v1/entries_pb"
import { entryKindMeta } from "@/lib/entry-kinds"
import { copySecret } from "@/lib/clipboard"
import { openEntry, vaultIdScope } from "@/lib/vault-crypto"
import { TotpDisplay } from "@/components/vault/TotpDisplay"
import { useAuthStore } from "@/stores/auth"
import { useVaultStore } from "@/stores/vault"

export default function EntryDetailPage({ entryId }: { entryId: string }) {
  const userId = useAuthStore((s) => s.userId ?? s.email ?? "")
  const vaultKey = useVaultStore((s) => s.vaultKey)
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [showDelete, setShowDelete] = useState(false)

  const detailQ = useQuery({
    enabled: !!vaultKey,
    queryKey: ["entries", "detail", entryId],
    queryFn: async () => {
      if (!vaultKey) throw new Error("vault locked")
      const r = await entriesClient.getEntry({ id: entryId })
      if (!r.entry) throw new Error("not found")
      const pt = await openEntry({
        vaultKey,
        vaultId: vaultIdScope(userId),
        entryId: r.entry.id,
        version: r.entry.version,
        encryptedBlob: r.entry.encryptedBlob,
        wrappedItemKey: r.entry.wrappedItemKey,
      })
      return { entry: r.entry, plaintext: pt }
    },
  })

  const deleteMut = useMutation({
    mutationFn: async () =>
      entriesClient.deleteEntry(
        { id: entryId },
        { headers: idempotencyHeaders() }
      ),
    onSuccess: async () => {
      toast.success("Item deleted")
      await qc.invalidateQueries({ queryKey: ["entries"] })
      await navigate({ to: "/entries" })
    },
    onError: (err) => toast.error(`Delete failed: ${(err as Error).message}`),
  })

  if (detailQ.isLoading) {
    return <p className="text-sm text-muted-foreground">Decrypting…</p>
  }
  if (detailQ.error || !detailQ.data) {
    return (
      <p className="text-sm text-destructive">
        Failed: {(detailQ.error as Error)?.message ?? "unknown"}
      </p>
    )
  }

  const { entry, plaintext } = detailQ.data
  const meta = entryKindMeta(entry.kind)

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <header className="flex flex-wrap items-start justify-between gap-2">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <meta.Icon className={`size-5 ${meta.color}`} />
            <span className="text-sm text-muted-foreground">{meta.label}</span>
          </div>
          <h1 className="text-2xl font-semibold tracking-tight">
            {plaintext.title}
          </h1>
          <div className="flex gap-1">
            {entry.isFavorite && <Badge>Favorite</Badge>}
            {entry.hasTotp && <Badge variant="secondary">TOTP</Badge>}
          </div>
        </div>
        <div className="flex gap-2">
          <Link
            to="/entries/$entryId/edit"
            params={{ entryId: entry.id }}
            className={buttonVariants({ variant: "outline" })}
          >
            <Pencil className="size-4" />
            Edit
          </Link>
          <Button variant="destructive" onClick={() => setShowDelete(true)}>
            <Trash2 className="size-4" />
            Delete
          </Button>
        </div>
      </header>

      {entry.kind === EntryKind.LOGIN && (
        <Card>
          <CardHeader>
            <CardTitle>Credentials</CardTitle>
            <CardDescription>
              Click a copy icon to put it on the clipboard.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <FieldRow label="Username" value={plaintext.username} />
            <FieldRow label="Password" value={plaintext.password} secret />
            <FieldRow label="URL" value={plaintext.url} link />
            {plaintext.totpSecret && (
              <>
                <div className="rounded-md border bg-muted/40 px-3 py-2">
                  <div className="mb-2 text-xs tracking-wide text-muted-foreground uppercase">
                    One-time code
                  </div>
                  <TotpDisplay
                    secret={plaintext.totpSecret}
                    period={plaintext.totpPeriod}
                    digits={plaintext.totpDigits}
                  />
                </div>
                <FieldRow
                  label="TOTP secret"
                  value={plaintext.totpSecret}
                  secret
                />
              </>
            )}
          </CardContent>
        </Card>
      )}

      {entry.kind === EntryKind.TOTP && (
        <Card>
          <CardHeader>
            <CardTitle>Authenticator</CardTitle>
            <CardDescription>
              Code refreshes every {plaintext.totpPeriod ?? 30} seconds.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {plaintext.totpSecret ? (
              <TotpDisplay
                secret={plaintext.totpSecret}
                period={plaintext.totpPeriod}
                digits={plaintext.totpDigits}
              />
            ) : (
              <p className="text-sm text-muted-foreground">
                No TOTP secret stored on this entry.
              </p>
            )}
            <FieldRow
              label="Secret (base32)"
              value={plaintext.totpSecret}
              secret
            />
          </CardContent>
        </Card>
      )}

      {entry.kind === EntryKind.CARD && (
        <Card>
          <CardHeader>
            <CardTitle>Card</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <FieldRow label="Number" value={plaintext.cardNumber} secret />
            <FieldRow label="Cardholder" value={plaintext.cardHolder} />
            <FieldRow label="Expiry" value={plaintext.cardExpiry} />
            <FieldRow label="CVV" value={plaintext.cardCvv} secret />
          </CardContent>
        </Card>
      )}

      {entry.kind === EntryKind.IDENTITY && (
        <Card>
          <CardHeader>
            <CardTitle>Identity</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <FieldRow label="Full name" value={plaintext.fullName} />
            <FieldRow label="Email" value={plaintext.email} />
            <FieldRow label="Phone" value={plaintext.phone} />
            <FieldRow label="Address" value={plaintext.address} />
          </CardContent>
        </Card>
      )}

      {entry.kind === EntryKind.SSH_KEY && (
        <Card>
          <CardHeader>
            <CardTitle>SSH key</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <FieldRow
              label="Public key"
              value={plaintext.publicKey}
              multiline
            />
            <FieldRow
              label="Private key"
              value={plaintext.privateKey}
              multiline
              secret
            />
            <FieldRow label="Passphrase" value={plaintext.passphrase} secret />
          </CardContent>
        </Card>
      )}

      {plaintext.notesMd && (
        <Card>
          <CardHeader>
            <CardTitle>Notes</CardTitle>
            <CardDescription>
              Markdown rendering arrives in Sprint 5.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <pre className="font-sans text-sm whitespace-pre-wrap">
              {plaintext.notesMd}
            </pre>
          </CardContent>
        </Card>
      )}

      <Dialog open={showDelete} onOpenChange={setShowDelete}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete this item?</DialogTitle>
            <DialogDescription>
              This action is irreversible. The ciphertext is removed; backups
              become unreadable once the wrapped vault key rotates out.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setShowDelete(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => deleteMut.mutate()}
              disabled={deleteMut.isPending}
            >
              {deleteMut.isPending ? "Deleting…" : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

function FieldRow({
  label,
  value,
  secret,
  link,
  multiline,
}: {
  label: string
  value: string | undefined
  secret?: boolean
  link?: boolean
  multiline?: boolean
}) {
  const [show, setShow] = useState(!secret)
  if (!value) return null
  const display = show ? value : "•".repeat(Math.min(12, value.length))
  return (
    <div className="flex items-start gap-3">
      <div className="w-32 shrink-0 pt-1.5 text-xs tracking-wide text-muted-foreground uppercase">
        {label}
      </div>
      <div className="min-w-0 flex-1">
        {multiline ? (
          <pre className="rounded-md border bg-muted px-2 py-1.5 font-mono text-xs whitespace-pre-wrap">
            {display}
          </pre>
        ) : (
          <p className="rounded-md border bg-muted px-2 py-1.5 font-mono text-sm break-all">
            {display}
          </p>
        )}
      </div>
      <div className="flex gap-1">
        {secret && (
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setShow((v) => !v)}
            aria-label={show ? "Hide" : "Show"}
          >
            {show ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
          </Button>
        )}
        {link && /^https?:/i.test(value) && (
          <a
            href={value}
            target="_blank"
            rel="noopener noreferrer"
            className={buttonVariants({ variant: "ghost", size: "icon" })}
            aria-label="Open link"
          >
            <ExternalLink className="size-4" />
          </a>
        )}
        <Button
          variant="ghost"
          size="icon"
          onClick={() => copySecret(value, { label: label.toLowerCase() })}
          aria-label={`Copy ${label}`}
        >
          <Copy className="size-4" />
        </Button>
      </div>
    </div>
  )
}

// Entry create / edit form. The visible field set depends on `kind`.
// Saving seals the plaintext into encrypted_blob + wrapped_item_key and
// computes title_hash (and domain_hash for logins) before calling the API.

import { useEffect, useMemo, useState } from "react"
import { useNavigate } from "@tanstack/react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"

import { entriesClient, idempotencyHeaders, projectsClient } from "@/api/client"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import { EntryKind } from "@/api/gen/oblivio/v1/entries_pb"
import { ENTRY_KINDS } from "@/lib/entry-kinds"
import {
  openEntry,
  openProject,
  sealEntry,
  vaultIdScope,
} from "@/lib/vault-crypto"
import type { EntryPlaintext } from "@/lib/vault-crypto"
import { useAuthStore } from "@/stores/auth"
import { useVaultStore } from "@/stores/vault"

export type EntryFormMode =
  | { mode: "create"; defaultKind?: EntryKind }
  | { mode: "edit"; entryId: string }

const EMPTY_PT: EntryPlaintext = { title: "" }

export default function EntryForm(props: EntryFormMode) {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const userId = useAuthStore((s) => s.userId ?? s.email ?? "")
  const vaultKey = useVaultStore((s) => s.vaultKey)
  const vaultId = vaultIdScope(userId)

  const [kind, setKind] = useState<EntryKind>(
    props.mode === "create" ? (props.defaultKind ?? EntryKind.LOGIN) : EntryKind.LOGIN,
  )
  const [projectId, setProjectId] = useState<string>("")
  const [isFavorite, setIsFavorite] = useState(false)
  const [pt, setPt] = useState<EntryPlaintext>(EMPTY_PT)
  const [error, setError] = useState<string | null>(null)

  const projectsQ = useQuery({
    queryKey: ["projects"],
    queryFn: () => projectsClient.listProjects({}),
  })

  const projectNamesQ = useQuery({
    enabled: !!vaultKey && !!projectsQ.data?.projects.length,
    queryKey: [
      "projects",
      "names",
      projectsQ.data?.projects.map((p) => p.id).join(","),
    ],
    queryFn: async (): Promise<Record<string, string>> => {
      if (!vaultKey || !projectsQ.data) return {}
      const names: Record<string, string> = {}
      await Promise.all(
        projectsQ.data.projects.map(async (p) => {
          try {
            const pt = await openProject({
              vaultKey,
              vaultId,
              projectId: p.id,
              version: p.version,
              encryptedBlob: p.encryptedBlob,
              wrappedItemKey: p.wrappedItemKey,
            })
            names[p.id] = pt.name
          } catch {
            names[p.id] = ""
          }
        }),
      )
      return names
    },
  })

  const existingQ = useQuery({
    enabled: props.mode === "edit" && !!vaultKey,
    queryKey: ["entries", "detail", props.mode === "edit" ? props.entryId : "_"],
    queryFn: async () => {
      if (props.mode !== "edit" || !vaultKey) throw new Error("not ready")
      const r = await entriesClient.getEntry({ id: props.entryId })
      if (!r.entry) throw new Error("entry not found")
      const decrypted = await openEntry({
        vaultKey,
        vaultId,
        entryId: r.entry.id,
        version: r.entry.version,
        encryptedBlob: r.entry.encryptedBlob,
        wrappedItemKey: r.entry.wrappedItemKey,
      })
      return { entry: r.entry, plaintext: decrypted }
    },
  })

  useEffect(() => {
    if (existingQ.data) {
      setKind(existingQ.data.entry.kind)
      setProjectId(existingQ.data.entry.projectId)
      setIsFavorite(existingQ.data.entry.isFavorite)
      setPt(existingQ.data.plaintext)
    }
  }, [existingQ.data])

  const hasTotp = useMemo(
    () => !!(pt.totpSecret && pt.totpSecret.trim().length > 0),
    [pt.totpSecret],
  )

  const saveMut = useMutation({
    mutationFn: async () => {
      if (!vaultKey) throw new Error("vault locked")
      const plaintext: EntryPlaintext = { ...pt, title: pt.title.trim() }
      if (!plaintext.title) throw new Error("title required")

      if (props.mode === "create") {
        const newId = crypto.randomUUID()
        const sealed = await sealEntry({
          vaultKey,
          vaultId,
          entryId: newId,
          version: 1,
          plaintext,
        })
        return entriesClient.createEntry(
          {
            projectId: projectId || undefined,
            kind,
            encryptedBlob: sealed.encryptedBlob,
            wrappedItemKey: sealed.wrappedItemKey,
            titleHash: sealed.titleHash,
            domainHash: sealed.domainHash ?? new Uint8Array(0),
            hasTotp,
            isFavorite,
          },
          { headers: idempotencyHeaders() },
        )
      }

      if (!existingQ.data) throw new Error("entry not loaded")
      const cur = existingQ.data.entry
      const nextVersion = cur.version + 1
      const sealed = await sealEntry({
        vaultKey,
        vaultId,
        entryId: cur.id,
        version: nextVersion,
        plaintext,
      })
      return entriesClient.updateEntry(
        {
          id: cur.id,
          expectedVersion: cur.version,
          projectId: projectId || undefined,
          kind,
          encryptedBlob: sealed.encryptedBlob,
          wrappedItemKey: sealed.wrappedItemKey,
          titleHash: sealed.titleHash,
          domainHash: sealed.domainHash ?? new Uint8Array(0),
          hasTotp,
          isFavorite,
        },
        { headers: idempotencyHeaders() },
      )
    },
    onSuccess: async () => {
      toast.success(props.mode === "create" ? "Item created" : "Item updated")
      await qc.invalidateQueries({ queryKey: ["entries"] })
      await navigate({ to: "/app/entries" })
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  })

  function set<K extends keyof EntryPlaintext>(k: K, v: EntryPlaintext[K]) {
    setPt((cur) => ({ ...cur, [k]: v }))
  }

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">
          {props.mode === "create" ? "New item" : "Edit item"}
        </h1>
        <p className="text-sm text-muted-foreground">
          All fields are encrypted under a fresh per-item key.
        </p>
      </header>

      <Card>
        <CardHeader>
          <CardTitle>Type & grouping</CardTitle>
          <CardDescription>
            Pick a kind — the form below adapts.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <div className="space-y-2">
            <Label>Kind</Label>
            <Select
              value={kind.toString()}
              onValueChange={(v) => v && setKind(Number(v) as EntryKind)}
              disabled={props.mode === "edit"}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {ENTRY_KINDS.map((m) => (
                  <SelectItem key={m.kind} value={m.kind.toString()}>
                    {m.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label>Project</Label>
            <Select
              value={projectId || "none"}
              onValueChange={(v) => setProjectId(!v || v === "none" ? "" : v)}
            >
              <SelectTrigger>
                <SelectValue placeholder="No project" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="none">(no project)</SelectItem>
                {projectsQ.data?.projects.map((p) => (
                  <SelectItem key={p.id} value={p.id}>
                    {projectNamesQ.data?.[p.id] || `Project ${p.id.slice(0, 8)}`}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Details</CardTitle>
          <CardDescription>
            {kind === EntryKind.NOTE
              ? "A free-form encrypted note."
              : "Per-kind plaintext fields."}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="title">Title</Label>
            <Input
              id="title"
              value={pt.title}
              onChange={(e) => set("title", e.target.value)}
              required
            />
          </div>

          {(kind === EntryKind.LOGIN || kind === EntryKind.IDENTITY) && (
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="username">Username</Label>
                <Input
                  id="username"
                  autoComplete="off"
                  value={pt.username ?? ""}
                  onChange={(e) => set("username", e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  autoComplete="off"
                  value={pt.password ?? ""}
                  onChange={(e) => set("password", e.target.value)}
                />
              </div>
              <div className="space-y-2 md:col-span-2">
                <Label htmlFor="url">URL</Label>
                <Input
                  id="url"
                  type="url"
                  placeholder="https://example.com"
                  value={pt.url ?? ""}
                  onChange={(e) => set("url", e.target.value)}
                />
              </div>
            </div>
          )}

          {kind === EntryKind.TOTP && (
            <div className="space-y-2">
              <Label htmlFor="totp">TOTP secret (base32)</Label>
              <Input
                id="totp"
                value={pt.totpSecret ?? ""}
                onChange={(e) => set("totpSecret", e.target.value)}
                autoComplete="off"
              />
            </div>
          )}

          {kind === EntryKind.LOGIN && (
            <div className="space-y-2">
              <Label htmlFor="login-totp">TOTP secret (optional)</Label>
              <Input
                id="login-totp"
                value={pt.totpSecret ?? ""}
                onChange={(e) => set("totpSecret", e.target.value)}
                autoComplete="off"
                placeholder="base32 — if this login uses TOTP 2FA"
              />
            </div>
          )}

          {kind === EntryKind.CARD && (
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <div className="space-y-2 md:col-span-2">
                <Label htmlFor="card-number">Card number</Label>
                <Input
                  id="card-number"
                  value={pt.cardNumber ?? ""}
                  onChange={(e) => set("cardNumber", e.target.value)}
                  autoComplete="off"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="card-holder">Cardholder</Label>
                <Input
                  id="card-holder"
                  value={pt.cardHolder ?? ""}
                  onChange={(e) => set("cardHolder", e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="card-expiry">Expiry MM/YY</Label>
                <Input
                  id="card-expiry"
                  value={pt.cardExpiry ?? ""}
                  onChange={(e) => set("cardExpiry", e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="card-cvv">CVV</Label>
                <Input
                  id="card-cvv"
                  type="password"
                  value={pt.cardCvv ?? ""}
                  onChange={(e) => set("cardCvv", e.target.value)}
                />
              </div>
            </div>
          )}

          {kind === EntryKind.IDENTITY && (
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="full-name">Full name</Label>
                <Input
                  id="full-name"
                  value={pt.fullName ?? ""}
                  onChange={(e) => set("fullName", e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  type="email"
                  value={pt.email ?? ""}
                  onChange={(e) => set("email", e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="phone">Phone</Label>
                <Input
                  id="phone"
                  value={pt.phone ?? ""}
                  onChange={(e) => set("phone", e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="address">Address</Label>
                <Input
                  id="address"
                  value={pt.address ?? ""}
                  onChange={(e) => set("address", e.target.value)}
                />
              </div>
            </div>
          )}

          {kind === EntryKind.SSH_KEY && (
            <div className="space-y-3">
              <div className="space-y-2">
                <Label htmlFor="public-key">Public key</Label>
                <Textarea
                  id="public-key"
                  rows={3}
                  value={pt.publicKey ?? ""}
                  onChange={(e) => set("publicKey", e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="private-key">Private key</Label>
                <Textarea
                  id="private-key"
                  rows={6}
                  value={pt.privateKey ?? ""}
                  onChange={(e) => set("privateKey", e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="passphrase">Passphrase</Label>
                <Input
                  id="passphrase"
                  type="password"
                  value={pt.passphrase ?? ""}
                  onChange={(e) => set("passphrase", e.target.value)}
                />
              </div>
            </div>
          )}

          <div className="space-y-2">
            <Label htmlFor="notes">Notes (markdown)</Label>
            <Textarea
              id="notes"
              rows={kind === EntryKind.NOTE ? 12 : 4}
              value={pt.notesMd ?? ""}
              onChange={(e) => set("notesMd", e.target.value)}
            />
          </div>

          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={isFavorite}
              onChange={(e) => setIsFavorite(e.target.checked)}
            />
            Mark as favorite
          </label>

          {error && <p className="text-sm text-destructive">{error}</p>}
        </CardContent>
      </Card>

      <div className="flex justify-end gap-2">
        <Button variant="ghost" onClick={() => navigate({ to: "/app/entries" })}>
          Cancel
        </Button>
        <Button
          onClick={() => {
            setError(null)
            saveMut.mutate()
          }}
          disabled={saveMut.isPending || (props.mode === "edit" && existingQ.isLoading)}
        >
          {saveMut.isPending ? "Saving…" : "Save"}
        </Button>
      </div>
    </div>
  )
}

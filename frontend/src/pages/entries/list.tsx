// Entries list. Server returns metadata only (no ciphertext payload).
// We fetch the full blob lazily when the user opens an item.

import { useMemo, useState } from "react"
import { Link } from "@tanstack/react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Filter, Plus, Search, Star, StarOff } from "lucide-react"
import { toast } from "sonner"

import { entriesClient, idempotencyHeaders, projectsClient } from "@/api/client"
import { Badge } from "@/components/ui/badge"
import { Button, buttonVariants } from "@/components/ui/button"
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { EntryKind, type EntryMeta } from "@/api/gen/oblivio/v1/entries_pb"
import { entryKindMeta, ENTRY_KINDS } from "@/lib/entry-kinds"
import {
  computeTitleHash,
  openEntry,
  openProject,
  vaultIdScope,
} from "@/lib/vault-crypto"
import { useAuthStore } from "@/stores/auth"
import { useVaultStore } from "@/stores/vault"

export type EntryListFilters = {
  projectId?: string
  kind?: EntryKind
  favorites?: boolean
  query?: string
}

export default function EntriesListPage({
  initial,
  pinKind,
}: {
  initial?: EntryListFilters
  // pinKind hides the kind selector and forces the filter (used by the
  // /notes route, which is just entries with kind=note).
  pinKind?: EntryKind
}) {
  const userId = useAuthStore((s) => s.userId ?? s.email ?? "")
  const vaultKey = useVaultStore((s) => s.vaultKey)
  const qc = useQueryClient()

  const [projectId, setProjectId] = useState<string | undefined>(
    initial?.projectId
  )
  const [kind, setKind] = useState<EntryKind | undefined>(
    pinKind ?? initial?.kind
  )
  const [favorites, setFavorites] = useState(initial?.favorites ?? false)
  const [query, setQuery] = useState(initial?.query ?? "")
  const [searchHash, setSearchHash] = useState<Uint8Array | undefined>(
    undefined
  )

  const projectsQ = useQuery({
    queryKey: ["projects"],
    queryFn: () => projectsClient.listProjects({}),
  })

  // Decrypt all project names once so every entry row can display a
  // human-readable project label instead of a raw UUID.
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
              vaultId: vaultIdScope(userId),
              projectId: p.id,
              version: p.version,
              encryptedBlob: p.encryptedBlob,
              wrappedItemKey: p.wrappedItemKey,
            })
            names[p.id] = pt.name
          } catch {
            names[p.id] = ""
          }
        })
      )
      return names
    },
  })

  const listQ = useQuery({
    queryKey: [
      "entries",
      { projectId, kind, favorites, searchHash: searchHash ? "yes" : "no" },
    ],
    queryFn: () =>
      entriesClient.listEntries({
        projectId,
        kind,
        favoritesOnly: favorites || undefined,
        titleHashes: searchHash ? [searchHash] : [],
        limit: 100,
      }),
  })

  // Decrypt titles for every metadata row in one batched GetEntriesByIds
  // call. The blobs are payload-cheap and we audit the batch as a single
  // entry_view event server-side.
  const ids = listQ.data?.entries.map((e) => e.id) ?? []
  const titlesQ = useQuery({
    enabled: !!vaultKey && ids.length > 0,
    queryKey: ["entries", "titles", ids.join(",")],
    queryFn: async (): Promise<Record<string, string>> => {
      if (!vaultKey || ids.length === 0) return {}
      const r = await entriesClient.getEntriesByIds({ ids })
      const titles: Record<string, string> = {}
      await Promise.all(
        r.entries.map(async (e) => {
          try {
            const pt = await openEntry({
              vaultKey,
              vaultId: vaultIdScope(userId),
              entryId: e.id,
              version: e.version,
              encryptedBlob: e.encryptedBlob,
              wrappedItemKey: e.wrappedItemKey,
            })
            titles[e.id] = pt.title
          } catch {
            titles[e.id] = ""
          }
        })
      )
      return titles
    },
  })

  const favoriteMut = useMutation({
    mutationFn: async (e: EntryMeta) =>
      entriesClient.toggleFavorite(
        { id: e.id, isFavorite: !e.isFavorite },
        { headers: idempotencyHeaders() }
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["entries"] }),
    onError: (err) => toast.error(`Toggle failed: ${(err as Error).message}`),
  })

  async function runSearch() {
    if (!vaultKey || !query.trim()) {
      setSearchHash(undefined)
      return
    }
    const h = await computeTitleHash(vaultKey, query.trim())
    setSearchHash(h)
  }

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">
            {pinKind === EntryKind.NOTE ? "Notes" : "Items"}
          </h1>
          <p className="text-sm text-muted-foreground">
            Server stores only ciphertext. Titles and details are decrypted in
            your browser when you open an item.
          </p>
        </div>
        <Link
          to="/app/entries/new"
          search={pinKind === EntryKind.NOTE ? { kind: "note" } : {}}
          className={buttonVariants()}
        >
          <Plus className="size-4" />
          {pinKind === EntryKind.NOTE ? "New note" : "New item"}
        </Link>
      </header>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-base">
            <Filter className="size-4" />
            Filters
          </CardTitle>
          <CardDescription>
            Exact-title search is server-side via a blind index; the server
            never sees the title itself.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid grid-cols-1 gap-3 md:grid-cols-4">
          <div className="space-y-2 md:col-span-2">
            <Label htmlFor="q">Title (exact match)</Label>
            <div className="flex gap-2">
              <Input
                id="q"
                placeholder="e.g. GitHub"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault()
                    void runSearch()
                  }
                }}
              />
              <Button variant="outline" onClick={runSearch}>
                <Search className="size-4" />
                Search
              </Button>
              {searchHash && (
                <Button
                  variant="ghost"
                  onClick={() => {
                    setQuery("")
                    setSearchHash(undefined)
                  }}
                >
                  Clear
                </Button>
              )}
            </div>
          </div>

          {!pinKind && (
            <div className="space-y-2">
              <Label>Kind</Label>
              <Select
                value={kind?.toString() ?? "all"}
                onValueChange={(v) =>
                  setKind(
                    !v || v === "all" ? undefined : (Number(v) as EntryKind)
                  )
                }
              >
                <SelectTrigger>
                  <SelectValue placeholder="All kinds" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All kinds</SelectItem>
                  {ENTRY_KINDS.map((m) => (
                    <SelectItem key={m.kind} value={m.kind.toString()}>
                      {m.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}

          <div className="space-y-2">
            <Label>Project</Label>
            <Select
              value={projectId ?? "all"}
              onValueChange={(v) =>
                setProjectId(!v || v === "all" ? undefined : v)
              }
            >
              <SelectTrigger>
                <SelectValue placeholder="All projects" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All projects</SelectItem>
                {projectsQ.data?.projects.map((p) => (
                  <ProjectOption
                    key={p.id}
                    id={p.id}
                    version={p.version}
                    encryptedBlob={p.encryptedBlob}
                    wrappedItemKey={p.wrappedItemKey}
                    vaultId={vaultIdScope(userId)}
                    vaultKey={vaultKey ?? undefined}
                  />
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="flex items-end">
            <Button
              variant={favorites ? "default" : "outline"}
              onClick={() => setFavorites((v) => !v)}
            >
              <Star className="size-4" />
              Favorites only
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="p-0">
          {listQ.isLoading && (
            <p className="py-8 text-center text-sm text-muted-foreground">
              Loading…
            </p>
          )}
          {!listQ.isLoading && listQ.data?.entries.length === 0 && (
            <p className="py-8 text-center text-sm text-muted-foreground">
              No items match the current filters.
            </p>
          )}
          {!!listQ.data?.entries.length && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Kind</TableHead>
                  <TableHead>Title</TableHead>
                  <TableHead>Project</TableHead>
                  <TableHead>Flags</TableHead>
                  <TableHead className="text-right">Updated</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {listQ.data.entries.map((e) => (
                  <EntryRow
                    key={e.id}
                    entry={e}
                    title={titlesQ.data?.[e.id]}
                    titlesLoading={titlesQ.isLoading}
                    projectName={
                      e.projectId
                        ? projectNamesQ.data?.[e.projectId]
                        : undefined
                    }
                    onToggleFav={() => favoriteMut.mutate(e)}
                  />
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

function EntryRow({
  entry,
  title,
  titlesLoading,
  projectName,
  onToggleFav,
}: {
  entry: EntryMeta
  title: string | undefined
  titlesLoading: boolean
  projectName: string | undefined
  onToggleFav: () => void
}) {
  const meta = entryKindMeta(entry.kind)
  const updated = entry.updatedAt
    ? new Date(Number(entry.updatedAt.seconds) * 1000).toLocaleString()
    : "—"
  // Server never sees the title; we batch-decrypt blobs and fall back to an
  // id-derived label until the decryption query lands.
  let label: string
  if (title) {
    label = title
  } else if (titlesLoading) {
    label = "Decrypting…"
  } else {
    label = `Item ${entry.id.slice(0, 8)}`
  }
  return (
    <TableRow>
      <TableCell>
        <span className="inline-flex items-center gap-2 text-xs">
          <meta.Icon className={`size-4 ${meta.color}`} />
          {meta.label}
        </span>
      </TableCell>
      <TableCell>
        <Link
          to="/app/entries/$entryId"
          params={{ entryId: entry.id }}
          className="font-medium underline-offset-2 hover:underline"
        >
          {label}
        </Link>
      </TableCell>
      <TableCell className="text-muted-foreground">
        {entry.projectId
          ? (projectName ?? `Project ${entry.projectId.slice(0, 8)}`)
          : "—"}
      </TableCell>
      <TableCell>
        <div className="flex gap-1">
          {entry.hasTotp && <Badge variant="secondary">TOTP</Badge>}
          {entry.isFavorite && <Badge>Favorite</Badge>}
        </div>
      </TableCell>
      <TableCell className="text-right">
        <div className="flex items-center justify-end gap-2 text-xs text-muted-foreground">
          {updated}
          <Button
            variant="ghost"
            size="icon"
            onClick={onToggleFav}
            aria-label={entry.isFavorite ? "Unfavorite" : "Favorite"}
          >
            {entry.isFavorite ? (
              <StarOff className="size-4" />
            ) : (
              <Star className="size-4" />
            )}
          </Button>
        </div>
      </TableCell>
    </TableRow>
  )
}

function ProjectOption({
  id,
  version,
  encryptedBlob,
  wrappedItemKey,
  vaultId,
  vaultKey,
}: {
  id: string
  version: number
  encryptedBlob: Uint8Array
  wrappedItemKey: Uint8Array
  vaultId: string
  vaultKey?: Uint8Array
}) {
  const decryptQ = useQuery({
    enabled: !!vaultKey,
    queryKey: ["projects", "decrypt", id, version],
    queryFn: async () => {
      if (!vaultKey) throw new Error("vault locked")
      return openProject({
        vaultKey,
        vaultId,
        projectId: id,
        version,
        encryptedBlob,
        wrappedItemKey,
      })
    },
  })
  const label = useMemo(() => {
    if (decryptQ.isLoading) return "Decrypting…"
    return decryptQ.data?.name ?? `Project ${id.slice(0, 8)}`
  }, [decryptQ, id])
  return <SelectItem value={id}>{label}</SelectItem>
}

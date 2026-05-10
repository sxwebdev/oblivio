// Authenticated dashboard. Tiles show vault counters and recent items,
// using TanStack Query for caching. All metadata (entry ids, kind, has_totp)
// comes from the server-side metadata endpoints; titles are decrypted
// client-side on demand.

import { Link } from "@tanstack/react-router"
import { useQuery } from "@tanstack/react-query"
import {
  FileText,
  FolderClosed,
  KeyRound,
  Plus,
  ShieldCheck,
  Star,
} from "lucide-react"

import { entriesClient, projectsClient } from "@/api/client"
import { buttonVariants } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { EntryKind } from "@/api/gen/oblivio/v1/entries_pb"
import { useAuthStore } from "@/stores/auth"

export default function Dashboard() {
  const email = useAuthStore((s) => s.email)

  const projectsQ = useQuery({
    queryKey: ["projects"],
    queryFn: () => projectsClient.listProjects({}),
  })

  const recentQ = useQuery({
    queryKey: ["entries", "recent"],
    queryFn: () => entriesClient.listEntries({ limit: 5 }),
  })

  const favoritesQ = useQuery({
    queryKey: ["entries", "favorites"],
    queryFn: () =>
      entriesClient.listEntries({ favoritesOnly: true, limit: 5 }),
  })

  const notesQ = useQuery({
    queryKey: ["entries", "notes-count"],
    queryFn: () =>
      entriesClient.listEntries({ kind: EntryKind.NOTE, limit: 1 }),
  })

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">
          Welcome back{email ? `, ${email}` : ""}
        </h1>
        <p className="text-sm text-muted-foreground">
          Everything below is decrypted in your browser — the server never
          sees plaintext.
        </p>
      </header>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Projects</CardTitle>
            <FolderClosed className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold">
              {projectsQ.data?.projects.length ?? "—"}
            </div>
            <CardDescription>
              <Link to="/app/projects" className="underline">
                Manage projects
              </Link>
            </CardDescription>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Recent items</CardTitle>
            <KeyRound className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold">
              {recentQ.data?.entries.length ?? "—"}
            </div>
            <CardDescription>
              <Link to="/app/entries" className="underline">
                Browse items
              </Link>
            </CardDescription>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Favorites</CardTitle>
            <Star className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold">
              {favoritesQ.data?.entries.length ?? "—"}
            </div>
            <CardDescription>
              <Link to="/app/entries" search={{ favorites: true }} className="underline">
                Show favorites
              </Link>
            </CardDescription>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Notes</CardTitle>
            <FileText className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold">
              {notesQ.data?.entries.length ?? "—"}
            </div>
            <CardDescription>
              <Link to="/app/notes" className="underline">
                Open notes
              </Link>
            </CardDescription>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle className="text-base">Quick actions</CardTitle>
            <CardDescription>Add or unlock items in one click.</CardDescription>
          </div>
          <ShieldCheck className="size-5 text-primary" />
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          <Link to="/app/entries/new" className={buttonVariants()}>
            <Plus className="size-4" />
            New item
          </Link>
          <Link
            to="/app/projects/new"
            className={buttonVariants({ variant: "outline" })}
          >
            <Plus className="size-4" />
            New project
          </Link>
          <Link
            to="/app/notes/new"
            className={buttonVariants({ variant: "outline" })}
          >
            <Plus className="size-4" />
            New note
          </Link>
        </CardContent>
      </Card>
    </div>
  )
}

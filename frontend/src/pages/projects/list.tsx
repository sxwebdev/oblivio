// Projects list. Server returns ciphertext + metadata; we decrypt names
// client-side and render them in a table with row actions.

import { useState } from "react"
import { Link, useNavigate } from "@tanstack/react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { FolderClosed, MoreVertical, Pencil, Plus, Trash2 } from "lucide-react"
import { toast } from "sonner"

import { idempotencyHeaders, projectsClient } from "@/api/client"
import { Button, buttonVariants } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { useAuthStore } from "@/stores/auth"
import { useVaultStore } from "@/stores/vault"
import { openProject, vaultIdScope } from "@/lib/vault-crypto"
import type { Project } from "@/api/gen/oblivio/v1/projects_pb"

export default function ProjectsListPage() {
  const userId = useAuthStore((s) => s.userId ?? s.email ?? "")
  const vaultKey = useVaultStore((s) => s.vaultKey)
  const qc = useQueryClient()
  const navigate = useNavigate()
  const [deleteTarget, setDeleteTarget] = useState<Project | null>(null)

  const listQ = useQuery({
    queryKey: ["projects"],
    queryFn: () => projectsClient.listProjects({}),
  })

  const deleteMut = useMutation({
    mutationFn: async (p: Project) =>
      projectsClient.deleteProject(
        { id: p.id, expectedVersion: p.version },
        { headers: idempotencyHeaders() },
      ),
    onSuccess: () => {
      toast.success("Project deleted")
      void qc.invalidateQueries({ queryKey: ["projects"] })
      void qc.invalidateQueries({ queryKey: ["entries"] })
      setDeleteTarget(null)
    },
    onError: (err) => {
      toast.error(`Delete failed: ${(err as Error).message}`)
    },
  })

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Projects</h1>
          <p className="text-sm text-muted-foreground">
            Group related items. Names are encrypted client-side.
          </p>
        </div>
        <Link to="/app/projects/new" className={buttonVariants()}>
          <Plus className="size-4" />
          New project
        </Link>
      </header>

      {listQ.isLoading && (
        <Card>
          <CardContent className="py-8 text-center text-sm text-muted-foreground">
            Loading projects…
          </CardContent>
        </Card>
      )}

      {!listQ.isLoading && listQ.data?.projects.length === 0 && (
        <Card>
          <CardHeader className="text-center">
            <CardTitle className="flex items-center justify-center gap-2">
              <FolderClosed className="size-5" />
              No projects yet
            </CardTitle>
            <CardDescription>
              Projects help you organize items by client, environment, or topic.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex justify-center">
            <Link to="/app/projects/new" className={buttonVariants()}>
              Create your first project
            </Link>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-3">
        {listQ.data?.projects.map((p) => (
          <ProjectCard
            key={p.id}
            project={p}
            vaultKey={vaultKey ?? undefined}
            vaultId={vaultIdScope(userId)}
            onEdit={() =>
              navigate({
                to: "/app/projects/$projectId/edit",
                params: { projectId: p.id },
              })
            }
            onDelete={() => setDeleteTarget(p)}
          />
        ))}
      </div>

      <Dialog
        open={deleteTarget !== null}
        onOpenChange={(open) => !open && setDeleteTarget(null)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete project?</DialogTitle>
            <DialogDescription>
              Items inside the project are kept but become unfiled.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="ghost"
              onClick={() => setDeleteTarget(null)}
              disabled={deleteMut.isPending}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => deleteTarget && deleteMut.mutate(deleteTarget)}
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

function ProjectCard({
  project,
  vaultKey,
  vaultId,
  onEdit,
  onDelete,
}: {
  project: Project
  vaultKey: Uint8Array | undefined
  vaultId: string
  onEdit: () => void
  onDelete: () => void
}) {
  const decryptQ = useQuery({
    enabled: !!vaultKey,
    queryKey: ["projects", "decrypt", project.id, project.version],
    queryFn: async () => {
      if (!vaultKey) throw new Error("vault locked")
      return openProject({
        vaultKey,
        vaultId,
        projectId: project.id,
        version: project.version,
        encryptedBlob: project.encryptedBlob,
        wrappedItemKey: project.wrappedItemKey,
      })
    },
  })

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-2">
        <div className="min-w-0">
          <CardTitle className="truncate">
            {decryptQ.isLoading
              ? "Decrypting…"
              : (decryptQ.data?.name ?? "(unreadable)")}
          </CardTitle>
          {decryptQ.data?.description && (
            <CardDescription className="line-clamp-2">
              {decryptQ.data.description}
            </CardDescription>
          )}
        </div>
        <DropdownMenu>
          <DropdownMenuTrigger
            render={(props) => (
              <Button variant="ghost" size="icon" {...props}>
                <MoreVertical className="size-4" />
              </Button>
            )}
          />
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={onEdit}>
              <Pencil className="size-4" />
              Edit
            </DropdownMenuItem>
            <DropdownMenuItem onClick={onDelete}>
              <Trash2 className="size-4" />
              Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </CardHeader>
      <CardContent className="flex items-center justify-between text-xs text-muted-foreground">
        <span>v{project.version}</span>
        <Link
          to="/app/entries"
          search={{ projectId: project.id }}
          className="underline"
        >
          View items
        </Link>
      </CardContent>
    </Card>
  )
}

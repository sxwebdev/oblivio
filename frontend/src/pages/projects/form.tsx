// Create / edit project form. Reused by both routes via the `mode` prop.

import { useEffect, useState } from "react"
import { useNavigate } from "@tanstack/react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"

import { idempotencyHeaders, projectsClient } from "@/api/client"
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
import { Textarea } from "@/components/ui/textarea"
import { useAuthStore } from "@/stores/auth"
import { useVaultStore } from "@/stores/vault"
import { openProject, sealProject, vaultIdScope } from "@/lib/vault-crypto"
import type { ProjectPlaintext } from "@/lib/vault-crypto"

export type ProjectFormMode =
  | { mode: "create" }
  | { mode: "edit"; projectId: string }

export default function ProjectForm(props: ProjectFormMode) {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const userId = useAuthStore((s) => s.userId ?? s.email ?? "")
  const vaultKey = useVaultStore((s) => s.vaultKey)
  const vaultId = vaultIdScope(userId)

  const [name, setName] = useState("")
  const [description, setDescription] = useState("")
  const [error, setError] = useState<string | null>(null)

  // For edit mode: fetch the existing project and decrypt its blob.
  const existingQ = useQuery({
    enabled: props.mode === "edit" && !!vaultKey,
    queryKey: ["projects", "decrypt", props.mode === "edit" ? props.projectId : "_"],
    queryFn: async () => {
      if (props.mode !== "edit" || !vaultKey) throw new Error("not ready")
      const r = await projectsClient.getProject({ id: props.projectId })
      if (!r.project) throw new Error("project not found")
      const pt = await openProject({
        vaultKey,
        vaultId,
        projectId: r.project.id,
        version: r.project.version,
        encryptedBlob: r.project.encryptedBlob,
        wrappedItemKey: r.project.wrappedItemKey,
      })
      return { project: r.project, plaintext: pt }
    },
  })

  useEffect(() => {
    if (existingQ.data) {
      setName(existingQ.data.plaintext.name)
      setDescription(existingQ.data.plaintext.description ?? "")
    }
  }, [existingQ.data])

  const saveMut = useMutation({
    mutationFn: async () => {
      if (!vaultKey) throw new Error("vault locked")
      const plaintext: ProjectPlaintext = {
        name: name.trim(),
        description: description.trim() || undefined,
      }
      if (!plaintext.name) throw new Error("name required")

      if (props.mode === "create") {
        const newId = crypto.randomUUID()
        const sealed = await sealProject({
          vaultKey,
          vaultId,
          projectId: newId,
          version: 1,
          plaintext,
        })
        return projectsClient.createProject(
          {
            encryptedBlob: sealed.encryptedBlob,
            wrappedItemKey: sealed.wrappedItemKey,
            nameHash: sealed.titleHash,
            sortOrder: 0,
          },
          { headers: idempotencyHeaders() },
        )
      }

      if (!existingQ.data) throw new Error("project not loaded")
      const cur = existingQ.data.project
      const nextVersion = cur.version + 1
      const sealed = await sealProject({
        vaultKey,
        vaultId,
        projectId: cur.id,
        version: nextVersion,
        plaintext,
      })
      return projectsClient.updateProject(
        {
          id: cur.id,
          expectedVersion: cur.version,
          encryptedBlob: sealed.encryptedBlob,
          wrappedItemKey: sealed.wrappedItemKey,
          nameHash: sealed.titleHash,
        },
        { headers: idempotencyHeaders() },
      )
    },
    onSuccess: async () => {
      toast.success(props.mode === "create" ? "Project created" : "Project updated")
      await qc.invalidateQueries({ queryKey: ["projects"] })
      await navigate({ to: "/app/projects" })
    },
    onError: (err) => {
      setError(err instanceof Error ? err.message : String(err))
    },
  })

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">
          {props.mode === "create" ? "New project" : "Edit project"}
        </h1>
        <p className="text-sm text-muted-foreground">
          Name and description are encrypted with a per-project item key.
        </p>
      </header>

      <Card>
        <CardHeader>
          <CardTitle>Details</CardTitle>
          <CardDescription>The server only sees ciphertext.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="name">Name</Label>
            <Input
              id="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="description">Description (optional)</Label>
            <Textarea
              id="description"
              rows={4}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>
          {error && <p className="text-sm text-destructive">{error}</p>}
        </CardContent>
      </Card>

      <div className="flex justify-end gap-2">
        <Button variant="ghost" onClick={() => navigate({ to: "/app/projects" })}>
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

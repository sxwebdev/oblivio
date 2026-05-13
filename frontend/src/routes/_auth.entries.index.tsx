import { createFileRoute } from "@tanstack/react-router"
import { z } from "zod"

import EntriesListPage from "@/pages/entries/list"
import { EntryKind } from "@/api/gen/oblivio/v1/entries_pb"

const search = z.object({
  projectId: z.string().optional(),
  kind: z.string().optional(),
  favorites: z.boolean().optional(),
})

export const Route = createFileRoute("/_auth/entries/")({
  validateSearch: search,
  component: EntriesIndexRoute,
})

function EntriesIndexRoute() {
  const { projectId, kind, favorites } = Route.useSearch()
  return (
    <EntriesListPage
      initial={{
        projectId,
        kind: kindFromString(kind),
        favorites,
      }}
    />
  )
}

function kindFromString(s: string | undefined): EntryKind | undefined {
  if (!s) return undefined
  switch (s) {
    case "login":
      return EntryKind.LOGIN
    case "totp":
      return EntryKind.TOTP
    case "card":
      return EntryKind.CARD
    case "identity":
      return EntryKind.IDENTITY
    case "ssh_key":
      return EntryKind.SSH_KEY
    case "note":
      return EntryKind.NOTE
    default:
      return undefined
  }
}

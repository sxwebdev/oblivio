import { createFileRoute } from "@tanstack/react-router"
import { z } from "zod"

import EntryForm from "@/pages/entries/form"
import { EntryKind } from "@/api/gen/oblivio/v1/entries_pb"

const search = z.object({ kind: z.string().optional() })

export const Route = createFileRoute("/_auth/entries/new")({
  validateSearch: search,
  component: NewEntryRoute,
})

function NewEntryRoute() {
  const { kind } = Route.useSearch()
  let defaultKind: EntryKind | undefined
  switch (kind) {
    case "login":
      defaultKind = EntryKind.LOGIN
      break
    case "totp":
      defaultKind = EntryKind.TOTP
      break
    case "card":
      defaultKind = EntryKind.CARD
      break
    case "identity":
      defaultKind = EntryKind.IDENTITY
      break
    case "ssh_key":
      defaultKind = EntryKind.SSH_KEY
      break
    case "note":
      defaultKind = EntryKind.NOTE
      break
  }
  return <EntryForm mode="create" defaultKind={defaultKind} />
}

import { createFileRoute } from "@tanstack/react-router"

import EntryForm from "@/pages/entries/form"
import { EntryKind } from "@/api/gen/oblivio/v1/entries_pb"

export const Route = createFileRoute("/_auth/app/notes/new")({
  component: () => <EntryForm mode="create" defaultKind={EntryKind.NOTE} />,
})

import { createFileRoute } from "@tanstack/react-router"

import EntriesListPage from "@/pages/entries/list"
import { EntryKind } from "@/api/gen/oblivio/v1/entries_pb"

// Notes are entries with kind=note. We render the same list view with the
// kind filter forced.
export const Route = createFileRoute("/_auth/notes/")({
  component: () => <EntriesListPage pinKind={EntryKind.NOTE} />,
})

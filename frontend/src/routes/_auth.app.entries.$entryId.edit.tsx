import { createFileRoute } from "@tanstack/react-router"

import EntryForm from "@/pages/entries/form"

export const Route = createFileRoute("/_auth/app/entries/$entryId/edit")({
  component: () => {
    const { entryId } = Route.useParams()
    return <EntryForm mode="edit" entryId={entryId} />
  },
})

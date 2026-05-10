import { createFileRoute } from "@tanstack/react-router"

import EntryDetailPage from "@/pages/entries/detail"

export const Route = createFileRoute("/_auth/app/entries/$entryId/")({
  component: () => {
    const { entryId } = Route.useParams()
    return <EntryDetailPage entryId={entryId} />
  },
})

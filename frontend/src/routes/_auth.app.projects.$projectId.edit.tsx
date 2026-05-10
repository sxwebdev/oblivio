import { createFileRoute } from "@tanstack/react-router"

import ProjectForm from "@/pages/projects/form"

export const Route = createFileRoute("/_auth/app/projects/$projectId/edit")({
  component: EditProjectRoute,
})

function EditProjectRoute() {
  const { projectId } = Route.useParams()
  return <ProjectForm mode="edit" projectId={projectId} />
}

import { createFileRoute } from "@tanstack/react-router"

import ProjectForm from "@/pages/projects/form"

export const Route = createFileRoute("/_auth/app/projects/new")({
  component: () => <ProjectForm mode="create" />,
})

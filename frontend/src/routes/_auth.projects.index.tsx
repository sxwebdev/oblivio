import { createFileRoute } from "@tanstack/react-router"

import ProjectsListPage from "@/pages/projects/list"

export const Route = createFileRoute("/_auth/projects/")({
  component: ProjectsListPage,
})

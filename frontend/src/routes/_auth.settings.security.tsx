import { createFileRoute } from "@tanstack/react-router"

import SecurityPage from "@/pages/settings/security"

export const Route = createFileRoute("/_auth/settings/security")({
  component: SecurityPage,
})

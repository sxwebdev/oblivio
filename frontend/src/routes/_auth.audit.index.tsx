import { createFileRoute } from "@tanstack/react-router"

import AuditPage from "@/pages/audit"

export const Route = createFileRoute("/_auth/audit/")({
  component: AuditPage,
})

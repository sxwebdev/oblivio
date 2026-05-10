import { createFileRoute } from "@tanstack/react-router"

import RecoverPage from "@/pages/recover"

export const Route = createFileRoute("/_public/recover")({
  component: RecoverPage,
})

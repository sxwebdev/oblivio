import { createFileRoute } from "@tanstack/react-router"

import TwoFactorPage from "@/pages/settings/two-factor"

export const Route = createFileRoute("/_auth/settings/two-factor")({
  component: TwoFactorPage,
})

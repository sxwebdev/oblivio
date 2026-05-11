import { createFileRoute } from "@tanstack/react-router"

import VerifyEmailPage from "@/pages/verify-email"

// search-param schema: ?token=...
type Search = { token?: string }

export const Route = createFileRoute("/_public/verify-email")({
  component: VerifyEmailPage,
  validateSearch: (search: Record<string, unknown>): Search => ({
    token: typeof search.token === "string" ? search.token : undefined,
  }),
})

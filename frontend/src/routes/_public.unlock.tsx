import { createFileRoute } from "@tanstack/react-router"

import UnlockPage from "@/pages/unlock"

// Unlock screen lives under _public because a locked-but-authenticated
// vault has no rendered shell. It only checks that an access token is
// present; the master password is verified locally via the verifier.
export const Route = createFileRoute("/_public/unlock")({
  component: UnlockPage,
})

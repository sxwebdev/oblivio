import { Outlet, createFileRoute, redirect } from "@tanstack/react-router"

import { AppShell } from "@/components/layout/AppShell"
import { AutoLock } from "@/components/auth/AutoLock"
import { useChangeSubscription } from "@/api/subscriptions"
import { useAuthStore } from "@/stores/auth"
import { useVaultStore } from "@/stores/vault"

// _auth gates the protected area. Any nested route requires (a) a valid
// access token AND (b) an unlocked vault. Missing token → /login; locked
// vault → /unlock (so we don't lose the session on auto-lock).
export const Route = createFileRoute("/_auth")({
  beforeLoad: ({ location }) => {
    if (!useAuthStore.getState().isAuthenticated()) {
      throw redirect({ to: "/login" })
    }
    if (
      !useVaultStore.getState().isUnlocked() &&
      !location.pathname.startsWith("/unlock")
    ) {
      throw redirect({ to: "/unlock" })
    }
  },
  component: AuthLayout,
})

function AuthLayout() {
  // Open the server-streaming notification channel for the duration of
  // the authenticated session. Backgrounds itself; clean-up runs when
  // the layout unmounts (logout, lock, navigation to /_public).
  useChangeSubscription()
  return (
    <AppShell>
      <AutoLock />
      <Outlet />
    </AppShell>
  )
}

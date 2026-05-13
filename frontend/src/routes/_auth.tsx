import { useEffect } from "react"
import {
  Outlet,
  createFileRoute,
  redirect,
  useNavigate,
} from "@tanstack/react-router"

import { AppShell } from "@/components/layout/AppShell"
import { AutoLock } from "@/components/auth/AutoLock"
import { useChangeSubscription } from "@/api/subscriptions"
import { useAuthStore } from "@/stores/auth"
import { useVaultStore } from "@/stores/vault"

// _auth gates the protected area. The `beforeLoad` hook handles the
// happy-path entry (route-transition time), and the `AuthGuard`
// component below handles the live case — when the user is already
// inside a protected route and the session/vault flips to invalid
// (server restart → 401 → store cleared, AutoLock fires, …).
//
// Without the live guard the previous code stayed on the broken page
// indefinitely after the store was cleared, which let mounted queries
// fan out into a refetch storm (see plan: Defect 2 + Defect 3).
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
  return (
    <AuthGuard>
      <AuthenticatedShell />
    </AuthGuard>
  )
}

// AuthGuard subscribes to the auth/vault stores and redirects whenever
// either invariant breaks. Rendering `null` while the redirect is in
// flight prevents children from re-mounting their queries during the
// navigation tick.
function AuthGuard({ children }: { children: React.ReactNode }) {
  const navigate = useNavigate()
  const accessToken = useAuthStore((s) => s.accessToken)
  const refreshToken = useAuthStore((s) => s.refreshToken)
  const vaultKey = useVaultStore((s) => s.vaultKey)

  useEffect(() => {
    if (!accessToken && !refreshToken) {
      void navigate({ to: "/login", replace: true })
      return
    }
    if (!accessToken || !vaultKey) {
      void navigate({ to: "/unlock", replace: true })
    }
  }, [accessToken, refreshToken, vaultKey, navigate])

  if (!accessToken || !vaultKey) return null
  return <>{children}</>
}

// AuthenticatedShell hosts the hooks that should ONLY run when the user
// is signed in AND the vault is unlocked. Co-locating them here means
// the subscription stream never opens against a stale session and
// AutoLock never fires from a locked state.
function AuthenticatedShell() {
  useChangeSubscription()
  return (
    <AppShell>
      <AutoLock />
      <Outlet />
    </AppShell>
  )
}

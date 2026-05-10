import { Outlet, createFileRoute, redirect } from "@tanstack/react-router"
import { useAuthStore } from "@/stores/auth"

// _auth gates the protected area: any nested route requires a valid access token.
export const Route = createFileRoute("/_auth")({
  beforeLoad: () => {
    if (!useAuthStore.getState().isAuthenticated()) {
      throw redirect({ to: "/login" })
    }
  },
  component: AuthLayout,
})

function AuthLayout() {
  return <Outlet />
}

import { createFileRoute, redirect } from "@tanstack/react-router"
import { useAuthStore } from "@/stores/auth"

// Root path "/" — routes the user to the dashboard if signed in, otherwise to login.
export const Route = createFileRoute("/")({
  beforeLoad: () => {
    const authed = useAuthStore.getState().isAuthenticated()
    if (authed) throw redirect({ to: "/app" })
    throw redirect({ to: "/login" })
  },
})

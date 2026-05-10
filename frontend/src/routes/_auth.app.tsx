import { Outlet, createFileRoute } from "@tanstack/react-router"

// /app layout — renders nothing on its own, just composes the AppShell from
// the parent _auth route and lets nested routes plug into the outlet.
export const Route = createFileRoute("/_auth/app")({
  component: () => <Outlet />,
})

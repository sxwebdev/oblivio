import { createFileRoute } from "@tanstack/react-router"
import AppHome from "@/pages/app-home"

export const Route = createFileRoute("/_auth/app")({
  component: AppHome,
})

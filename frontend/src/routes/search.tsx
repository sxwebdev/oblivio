import { createFileRoute, redirect } from "@tanstack/react-router";
import Search from "@/pages/Search";
import { sessionStore } from "@/state/session";

export const Route = createFileRoute("/search")({
  beforeLoad: () => {
    if (!sessionStore.state.isAuthed) throw redirect({ to: "/login" });
  },
  component: Search,
});

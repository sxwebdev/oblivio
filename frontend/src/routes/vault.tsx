import { createFileRoute, redirect } from "@tanstack/react-router";
import VaultList from "@/pages/VaultList";
import { sessionStore } from "@/state/session";

export const Route = createFileRoute("/vault")({
  beforeLoad: () => {
    if (!sessionStore.state.isAuthed) throw redirect({ to: "/login" });
  },
  component: VaultList,
});

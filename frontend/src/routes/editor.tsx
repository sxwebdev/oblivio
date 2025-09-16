import { createFileRoute, redirect } from "@tanstack/react-router";
import ItemEditor from "@/pages/ItemEditor";
import { sessionStore } from "@/state/session";

export const Route = createFileRoute("/editor")({
  beforeLoad: () => {
    if (!sessionStore.state.isAuthed) throw redirect({ to: "/login" });
  },
  component: ItemEditor,
});

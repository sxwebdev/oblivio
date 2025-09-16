import { createFileRoute, redirect } from "@tanstack/react-router";
import SettingsAlerts from "@/pages/SettingsAlerts";
import { sessionStore } from "@/state/session";

export const Route = createFileRoute("/settings/alerts")({
  beforeLoad: () => {
    if (!sessionStore.state.isAuthed) throw redirect({ to: "/login" });
  },
  component: SettingsAlerts,
});

import { createFileRoute } from "@tanstack/react-router";
import { Link } from "@tanstack/react-router";
import { sessionStore } from "@/state/session";
import { useSyncExternalStore } from "react";

export const Route = createFileRoute("/")({
  component: App,
});

function App() {
  const authed = useSyncExternalStore(
    sessionStore.subscribe,
    () => sessionStore.state.isAuthed,
  );
  return (
    <div className="space-y-4 py-10">
      <h1 className="text-3xl font-bold tracking-tight">Oblivio</h1>
      <p className="text-muted-foreground max-w-prose">
        Zero-knowledge personal vault. Your secrets are encrypted end-to-end.
        Nothing sensitive is ever stored in the browser between sessions.
      </p>
      {authed ? (
        <div className="flex flex-wrap gap-3">
          <Link to="/vault" className="underline">
            Open Vault
          </Link>
          <Link to="/editor" className="underline">
            New Item
          </Link>
          <Link to="/search" className="underline">
            Search
          </Link>
          <Link to="/settings/alerts" className="underline">
            Alerts
          </Link>
        </div>
      ) : (
        <div className="flex flex-wrap gap-3">
          <Link to="/login" className="underline">
            Login
          </Link>
          <Link to="/register" className="underline">
            Register
          </Link>
        </div>
      )}
    </div>
  );
}

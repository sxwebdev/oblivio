import { Link } from "@tanstack/react-router";
import { logout, sessionStore } from "@/state/session";
import { zeroizeCrypto } from "@/state/crypto";
import { useSyncExternalStore } from "react";
import { authLogout, setAuthToken } from "@/api/client";

export default function Header() {
  const authed = useSyncExternalStore(
    sessionStore.subscribe,
    () => sessionStore.state.isAuthed,
  );
  return (
    <header className="flex justify-between gap-2 bg-white p-2 text-black">
      <nav className="flex flex-row">
        <div className="px-2 font-bold">
          <Link to="/">Home</Link>
        </div>
        {authed ? (
          <>
            <div className="px-2 font-bold">
              <Link to="/vault">Vault</Link>
            </div>
            <div className="px-2 font-bold">
              <Link to="/editor">Editor</Link>
            </div>
            <div className="px-2 font-bold">
              <Link to="/search">Search</Link>
            </div>
            <div className="px-2 font-bold">
              <Link to="/settings/alerts">Alerts</Link>
            </div>
          </>
        ) : (
          <>
            <div className="px-2 font-bold">
              <Link to="/login">Login</Link>
            </div>
            <div className="px-2 font-bold">
              <Link to="/register">Register</Link>
            </div>
          </>
        )}
      </nav>
      <div className="ml-auto">{authed ? <LockButton /> : null}</div>
    </header>
  );
}

function LockButton() {
  return (
    <button
      onClick={async () => {
        try {
          await authLogout();
        } catch {}
        setAuthToken(undefined);
        zeroizeCrypto();
        logout();
      }}
      className="ml-auto rounded bg-black px-3 py-1 text-white hover:opacity-80"
      title="Lock"
    >
      Lock
    </button>
  );
}

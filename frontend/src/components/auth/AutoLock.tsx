// AutoLock listens for inactivity, tab visibility changes, and page
// unload, then locks the vault (zeroizes vault_key in the Zustand store).
// The user is redirected to the unlock screen on the next render that
// requires a vault_key.
//
// Tunables live in lib/auto-lock-config.ts. Defaults follow the plan §10.3:
// 5 min idle + 60 s on hidden tab + immediate on unload.

import { useEffect, useRef } from "react";
import { useNavigate } from "@tanstack/react-router";

import { useVaultStore } from "@/stores/vault";
import { cancelPendingClear } from "@/lib/clipboard";

const IDLE_MS = 5 * 60 * 1000;
const HIDDEN_MS = 60 * 1000;

const ACTIVITY_EVENTS = [
  "mousedown",
  "mousemove",
  "keydown",
  "scroll",
  "touchstart",
] as const;

export function AutoLock(): null {
  const lock = useVaultStore((s) => s.lock);
  const navigate = useNavigate();
  const idleTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const hiddenTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    function doLock() {
      cancelPendingClear();
      lock();
      void navigate({ to: "/unlock" });
    }

    function resetIdle() {
      if (idleTimer.current) clearTimeout(idleTimer.current);
      idleTimer.current = setTimeout(doLock, IDLE_MS);
    }

    function onVisibility() {
      if (document.hidden) {
        if (hiddenTimer.current) clearTimeout(hiddenTimer.current);
        hiddenTimer.current = setTimeout(doLock, HIDDEN_MS);
      } else if (hiddenTimer.current) {
        clearTimeout(hiddenTimer.current);
        hiddenTimer.current = null;
        resetIdle();
      }
    }

    function onUnload() {
      // Synchronous best-effort zeroize. lock() also clears the Uint8Array.
      lock();
    }

    for (const ev of ACTIVITY_EVENTS) {
      window.addEventListener(ev, resetIdle, { passive: true });
    }
    document.addEventListener("visibilitychange", onVisibility);
    window.addEventListener("beforeunload", onUnload);

    resetIdle();

    return () => {
      for (const ev of ACTIVITY_EVENTS) {
        window.removeEventListener(ev, resetIdle);
      }
      document.removeEventListener("visibilitychange", onVisibility);
      window.removeEventListener("beforeunload", onUnload);
      if (idleTimer.current) clearTimeout(idleTimer.current);
      if (hiddenTimer.current) clearTimeout(hiddenTimer.current);
    };
  }, [lock, navigate]);

  return null;
}

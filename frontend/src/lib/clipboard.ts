// Clipboard helpers with auto-clear (plan §10.4).
//
// We write to the system clipboard, then 30 seconds later check whether
// the clipboard still holds the same value and, if so, blank it. The
// readText check prevents trampling on text the user copied in the
// meantime — which would otherwise be a small annoyance for the user.

import { toast } from "sonner";

const DEFAULT_CLEAR_MS = 30_000;

let pendingTimer: ReturnType<typeof setTimeout> | null = null;

export type CopyOptions = {
  // Label shown in the toast (e.g. "password", "TOTP code").
  label: string;
  // Override auto-clear timeout (ms). Pass 0 to skip clearing.
  clearAfterMs?: number;
};

// copySecret writes the value to the clipboard and schedules an auto-clear.
// If `clipboard-read` permission is unavailable (private windows, mobile)
// the clear still runs but cannot verify — we blank unconditionally.
export async function copySecret(value: string, opts: CopyOptions): Promise<void> {
  if (!value) {
    toast.error("Nothing to copy");
    return;
  }
  try {
    await navigator.clipboard.writeText(value);
  } catch (err) {
    toast.error(`Copy failed: ${(err as Error).message ?? "unknown"}`);
    return;
  }

  const clearMs = opts.clearAfterMs ?? DEFAULT_CLEAR_MS;
  toast.success(`Copied ${opts.label}`, {
    description:
      clearMs > 0
        ? `Auto-clear in ${Math.round(clearMs / 1000)}s`
        : "No auto-clear",
  });

  if (clearMs <= 0) return;

  if (pendingTimer) clearTimeout(pendingTimer);
  pendingTimer = setTimeout(async () => {
    try {
      const current = await navigator.clipboard.readText();
      if (current === value) {
        await navigator.clipboard.writeText("");
      }
    } catch {
      // Permission denied — blank anyway so we don't leak.
      try {
        await navigator.clipboard.writeText("");
      } catch {
        /* nothing else to do */
      }
    } finally {
      pendingTimer = null;
    }
  }, clearMs);
}

// cancelPendingClear lets the lock action wipe the timer without flushing
// the user's clipboard prematurely. Called from lockVault().
export function cancelPendingClear(): void {
  if (pendingTimer) {
    clearTimeout(pendingTimer);
    pendingTimer = null;
  }
}

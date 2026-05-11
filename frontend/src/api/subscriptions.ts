// Server-streaming bridge: SubscriptionsService.Subscribe → TanStack Query
// invalidation. The stream pushes "your entries/projects changed" hints
// from Postgres LISTEN/NOTIFY; this module turns those hints into cache
// invalidations so any mounted query refetches on the next tick.
//
// The stream is best-effort: a drop is recovered by exponential backoff
// + a fresh Subscribe call. On every reconnect we invalidate both query
// keys preemptively so a missed event during the disconnect window
// doesn't leave the UI stale.

import { useEffect } from "react"
import { useQueryClient, type QueryClient } from "@tanstack/react-query"

import { subscriptionsClient } from "@/api/client"
import { useAuthStore } from "@/stores/auth"
import { NotificationKind } from "@/api/gen/oblivio/v1/subscriptions_pb"

const initialDelay = 500
const maxDelay = 30_000

// runSubscriptionLoop opens the stream and dispatches notifications. Returns
// a function that aborts the loop. Internal — useChangeSubscription wraps it.
function runSubscriptionLoop(qc: QueryClient): () => void {
  const ctl = new AbortController()
  let delay = initialDelay

  const loop = async () => {
    while (!ctl.signal.aborted) {
      try {
        const stream = subscriptionsClient.subscribe({}, { signal: ctl.signal })
        // Invalidate on connect so a disconnect-window-missed event still
        // refreshes the UI promptly.
        qc.invalidateQueries({ queryKey: ["entries"] })
        qc.invalidateQueries({ queryKey: ["projects"] })
        for await (const resp of stream) {
          const kind = resp.notification?.kind
          switch (kind) {
            case NotificationKind.ENTRIES_UPDATED:
              qc.invalidateQueries({ queryKey: ["entries"] })
              break
            case NotificationKind.PROJECTS_UPDATED:
              qc.invalidateQueries({ queryKey: ["projects"] })
              break
            // HEARTBEAT and UNSPECIFIED → no-op; the stream stays open.
          }
          // Successful traffic resets the backoff window.
          delay = initialDelay
        }
      } catch {
        // Reconnect with capped exponential backoff. Cancellation
        // (ctl.signal.aborted) exits the outer while.
      }
      if (ctl.signal.aborted) return
      await new Promise((r) => setTimeout(r, delay))
      delay = Math.min(delay * 2, maxDelay)
    }
  }

  void loop()
  return () => ctl.abort()
}

// useChangeSubscription opens the per-user notification stream whenever the
// caller is authenticated. Mounting it once at the authenticated layout
// covers every entries/projects screen.
export function useChangeSubscription(): void {
  const qc = useQueryClient()
  const accessToken = useAuthStore((s) => s.accessToken)
  useEffect(() => {
    if (!accessToken) return
    return runSubscriptionLoop(qc)
  }, [qc, accessToken])
}

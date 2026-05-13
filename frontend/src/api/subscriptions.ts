// Server-streaming bridge: SubscriptionsService.Subscribe → TanStack Query
// invalidation. The stream pushes "your entries/projects changed" hints
// from Postgres LISTEN/NOTIFY; this module turns those hints into cache
// invalidations so any mounted query refetches on the next tick.
//
// Behaviour after a backend restart (the regression the loop ignored):
//  • If the stream errors with Connect `Unauthenticated`, the user's
//    session is stale — we cannot recover by retrying. Clear the auth
//    store + lock the vault and exit; AuthGuard reacts to the store
//    change and redirects to /unlock.
//  • Cache invalidations only fire AFTER the first chunk arrives so a
//    doomed reconnect (backend down, token stale, …) does not fan out
//    into a refetch storm of every mounted ["entries"] / ["projects"]
//    query — the original cause of the Chrome freeze on tab navigation.
//  • Transport-level errors (network, ECONNREFUSED) back off with
//    jitter and surrender after `maxConsecutiveFailures` so an offline
//    backend does not keep a coroutine spinning forever.

import { useEffect } from "react"
import { useQueryClient, type QueryClient } from "@tanstack/react-query"
import { Code, ConnectError } from "@connectrpc/connect"

import { subscriptionsClient } from "@/api/client"
import { useAuthStore } from "@/stores/auth"
import { useVaultStore } from "@/stores/vault"
import {
  NotificationKind,
  type SubscribeResponse,
} from "@/api/gen/oblivio/v1/subscriptions_pb"

const INITIAL_DELAY_MS = 2_000
const MAX_DELAY_MS = 30_000
const MAX_CONSECUTIVE_FAILURES = 5

// Subscriber abstracts away the concrete Connect client so the unit
// test can drive a fake async-iterable stream. Production wiring uses
// `defaultSubscriber` below.
export type Subscriber = (signal: AbortSignal) => AsyncIterable<SubscribeResponse>

const defaultSubscriber: Subscriber = (signal) =>
  subscriptionsClient.subscribe({}, { signal })

// runSubscriptionLoop opens the stream and dispatches notifications.
// Returns an abort callback. Exported for direct unit testing.
export function runSubscriptionLoop(
  qc: QueryClient,
  subscriber: Subscriber = defaultSubscriber
): () => void {
  const ctl = new AbortController()
  let delay = INITIAL_DELAY_MS
  let consecutiveFailures = 0

  const loop = async () => {
    while (!ctl.signal.aborted) {
      try {
        const stream = subscriber(ctl.signal)
        let firstChunkSeen = false
        for await (const resp of stream) {
          // Invalidate ONLY on the first successful chunk. Doing this
          // on every reconnect attempt (the old behaviour) triggered a
          // refetch storm whenever the backend was stale.
          if (!firstChunkSeen) {
            firstChunkSeen = true
            qc.invalidateQueries({ queryKey: ["entries"] })
            qc.invalidateQueries({ queryKey: ["projects"] })
          }
          const kind = resp.notification?.kind
          switch (kind) {
            case NotificationKind.ENTRIES_UPDATED:
              qc.invalidateQueries({ queryKey: ["entries"] })
              break
            case NotificationKind.PROJECTS_UPDATED:
              qc.invalidateQueries({ queryKey: ["projects"] })
              break
            // HEARTBEAT and UNSPECIFIED → no-op.
          }
          delay = INITIAL_DELAY_MS
          consecutiveFailures = 0
        }
        // Stream ended cleanly (server closed normally). Treat as a
        // reconnect candidate; don't bump the failure counter.
      } catch (err) {
        if (ctl.signal.aborted) return
        if (
          err instanceof ConnectError &&
          err.code === Code.Unauthenticated
        ) {
          // Streaming-RPC 401s bypass the unary refresh interceptor in
          // client.ts. Tear down here so AuthGuard can redirect.
          useAuthStore.getState().clear()
          useVaultStore.getState().lock()
          return
        }
        consecutiveFailures += 1
        if (consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
          // Surrender. AuthGuard / page reload restarts the loop.
          return
        }
      }
      if (ctl.signal.aborted) return
      const jitter = delay * (0.8 + Math.random() * 0.4)
      await new Promise((r) => setTimeout(r, jitter))
      delay = Math.min(delay * 2, MAX_DELAY_MS)
    }
  }

  void loop()
  return () => ctl.abort()
}

// useChangeSubscription opens the per-user notification stream whenever
// the caller is authenticated AND the vault is unlocked. Mounting it
// inside AuthGuard covers every authenticated screen. Subscribing
// before vault unlock would only generate useless refetches.
export function useChangeSubscription(): void {
  const qc = useQueryClient()
  const accessToken = useAuthStore((s) => s.accessToken)
  const vaultKey = useVaultStore((s) => s.vaultKey)
  useEffect(() => {
    if (!accessToken || !vaultKey) return
    return runSubscriptionLoop(qc)
  }, [qc, accessToken, vaultKey])
}

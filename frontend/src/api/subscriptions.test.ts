// Regression coverage for the post-server-restart freeze.
//
// The bug: when the backend was restarted while the user was signed in,
// the subscription loop would (a) keep retrying, (b) invalidate every
// ["entries"] / ["projects"] query on each retry, (c) trigger a refetch
// storm that overwhelmed the main thread.
//
// The contract we now enforce:
//  1. A Connect `Unauthenticated` error from the stream tears down the
//     auth store and locks the vault, then EXITS the loop (no retries).
//  2. The loop does NOT invalidate cached queries on a failed connect —
//     only on the first chunk of a live stream.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { QueryClient } from "@tanstack/react-query"
import { Code, ConnectError } from "@connectrpc/connect"

import { runSubscriptionLoop, type Subscriber } from "./subscriptions"
import { useAuthStore } from "@/stores/auth"
import { useVaultStore } from "@/stores/vault"

// Helper: an async iterable that immediately throws the supplied error.
function failingStream(err: unknown): Subscriber {
  return () =>
    (async function* () {
      throw err
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
    })()
}

// Helper: pause to let microtasks settle (loop catch → cleanup).
const tick = () => new Promise<void>((r) => setTimeout(r, 0))

describe("runSubscriptionLoop", () => {
  let qc: QueryClient
  let invalidateSpy: ReturnType<typeof vi.spyOn>
  let clearSpy: ReturnType<typeof vi.spyOn>
  let lockSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    qc = new QueryClient()
    invalidateSpy = vi.spyOn(qc, "invalidateQueries")
    clearSpy = vi.spyOn(useAuthStore.getState(), "clear")
    lockSpy = vi.spyOn(useVaultStore.getState(), "lock")
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("clears auth + locks vault + exits loop on Unauthenticated", async () => {
    const err = new ConnectError("session expired", Code.Unauthenticated)
    const abort = runSubscriptionLoop(qc, failingStream(err))

    // Two ticks: one for the for-await to throw, one for the catch
    // branch to invoke the store mutations + return.
    await tick()
    await tick()

    expect(clearSpy).toHaveBeenCalledTimes(1)
    expect(lockSpy).toHaveBeenCalledTimes(1)
    // The loop returned by itself; the abort callback is a no-op now.
    abort()
  })

  it("does NOT invalidate query cache when a connect attempt fails", async () => {
    const err = new ConnectError("backend offline", Code.Unavailable)
    const abort = runSubscriptionLoop(qc, failingStream(err))

    // Let the first iteration fail.
    await tick()
    await tick()
    abort() // stop the loop before it falls into the backoff timer

    expect(invalidateSpy).not.toHaveBeenCalled()
  })

  it("invalidates cache only after a real chunk arrives", async () => {
    const stream: Subscriber = () =>
      (async function* () {
        yield { notification: { kind: 0 } } as never
      })()

    const abort = runSubscriptionLoop(qc, stream)
    await tick()
    await tick()
    abort()

    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ["entries"] })
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ["projects"] })
  })
})

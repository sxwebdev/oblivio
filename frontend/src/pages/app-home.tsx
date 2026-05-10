// Minimal authenticated landing page. Used to verify Sprint 1: the user is
// signed in, the vault_key is unlocked in memory, GetMyKeys round-trips
// through the Bearer interceptor.

import { useEffect, useState } from "react"
import { useNavigate } from "@tanstack/react-router"
import { authClient } from "@/api/client"
import { Button } from "@/components/ui/button"
import { useAuthStore } from "@/stores/auth"
import { useVaultStore } from "@/stores/vault"
import { unwrapVaultKey, importMasterKey } from "@oblivio/crypto"

export default function AppHome() {
  const navigate = useNavigate()
  const { email, accessExpiresAt, clear } = useAuthStore()
  const vaultKey = useVaultStore((s) => s.vaultKey)
  const lockVault = useVaultStore((s) => s.lock)
  const [keysOk, setKeysOk] = useState<"loading" | "ok" | "fail">("loading")
  const [keysMsg, setKeysMsg] = useState("")

  useEffect(() => {
    // Sanity-check GetMyKeys round-trip immediately after auth.
    void (async () => {
      try {
        const r = await authClient.getMyKeys({})
        const sample = vaultKey
          ? `vaultKey[0..3]=${Array.from(vaultKey.slice(0, 4))
              .map((b) => b.toString(16).padStart(2, "0"))
              .join("")}`
          : "(vault locked)"
        setKeysOk("ok")
        setKeysMsg(
          `verifier=${r.verifier.length}B, wrappedVaultKey=${r.wrappedVaultKey.length}B, vault_version=${r.vaultKeyVersion}, ${sample}`,
        )
      } catch (e) {
        setKeysOk("fail")
        setKeysMsg(e instanceof Error ? e.message : String(e))
      }
    })()
    // We deliberately do not depend on vaultKey here — the call is one-shot.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function handleLogout() {
    try {
      await authClient.logout({})
    } catch {
      /* server may already have revoked; ignore */
    }
    lockVault()
    clear()
    navigate({ to: "/login" })
  }

  // Reference imports so the bundler keeps them — used for round-trip helpers
  // we may surface in later sprints (vault unlock retry, etc).
  void importMasterKey
  void unwrapVaultKey

  return (
    <div className="mx-auto max-w-2xl space-y-6 p-8">
      <div>
        <h1 className="text-2xl font-semibold">Vault unlocked</h1>
        <p className="text-sm text-muted-foreground">
          Signed in as {email}. Access expires{" "}
          {accessExpiresAt
            ? new Date(accessExpiresAt).toLocaleString()
            : "(unknown)"}
          .
        </p>
      </div>

      <section className="rounded-md border p-4">
        <h2 className="mb-2 text-sm font-semibold">GetMyKeys round-trip</h2>
        {keysOk === "loading" && <p className="text-sm">querying…</p>}
        {keysOk === "ok" && (
          <p className="font-mono text-xs break-all text-green-600">
            {keysMsg}
          </p>
        )}
        {keysOk === "fail" && (
          <p className="font-mono text-xs break-all text-destructive">
            {keysMsg}
          </p>
        )}
      </section>

      <div className="flex gap-2">
        <Button variant="outline" onClick={() => lockVault()}>
          Lock vault
        </Button>
        <Button variant="destructive" onClick={handleLogout}>
          Sign out
        </Button>
      </div>
    </div>
  )
}

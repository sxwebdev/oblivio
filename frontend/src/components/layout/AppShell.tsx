// Application shell for authenticated routes: a sticky left navigation,
// a top bar with the user identity and a Lock button, and a main content
// area that renders the router outlet.

import { Link, useNavigate, useRouterState } from "@tanstack/react-router"
import {
  AppWindow,
  FileText,
  FolderClosed,
  KeyRound,
  LogOut,
  Lock,
  ScrollText,
  Settings,
  ShieldCheck,
} from "lucide-react"
import type { ReactNode } from "react"

import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { authClient } from "@/api/client"
import { cn } from "@/lib/utils"
import { useAuthStore } from "@/stores/auth"
import { useVaultStore } from "@/stores/vault"
import { cancelPendingClear } from "@/lib/clipboard"

const NAV = [
  { to: "/", label: "Dashboard", Icon: AppWindow },
  { to: "/projects", label: "Projects", Icon: FolderClosed },
  { to: "/entries", label: "Items", Icon: KeyRound },
  { to: "/notes", label: "Notes", Icon: FileText },
  { to: "/audit", label: "Audit log", Icon: ScrollText },
  { to: "/settings", label: "Settings", Icon: Settings },
] as const

export function AppShell({ children }: { children: ReactNode }) {
  const navigate = useNavigate()
  const email = useAuthStore((s) => s.email)
  const clearSession = useAuthStore((s) => s.clear)
  const lockVault = useVaultStore((s) => s.lock)
  const isUnlocked = useVaultStore((s) => s.vaultKey !== null)
  const pathname = useRouterState({ select: (s) => s.location.pathname })

  async function handleLock() {
    cancelPendingClear()
    lockVault()
    await navigate({ to: "/unlock" })
  }

  async function handleLogout() {
    try {
      await authClient.logout({})
    } catch {
      /* server may have revoked already */
    }
    cancelPendingClear()
    lockVault()
    clearSession()
    await navigate({ to: "/login" })
  }

  return (
    <div className="grid min-h-svh grid-cols-[260px_1fr] bg-background text-foreground">
      <aside className="border-r bg-muted/30">
        <div className="flex h-14 items-center gap-2 px-5 font-semibold tracking-tight">
          <ShieldCheck className="size-5 text-primary" />
          Oblivio
        </div>
        <Separator />
        <nav className="space-y-1 p-3">
          {NAV.map(({ to, label, Icon }) => {
            const active =
              to === "/"
                ? pathname === "/"
                : pathname === to || pathname.startsWith(`${to}/`)
            return (
              <Link
                key={to}
                to={to}
                className={cn(
                  "flex items-center gap-2 rounded-md px-3 py-2 text-sm transition-colors",
                  active
                    ? "bg-primary/10 text-foreground"
                    : "text-muted-foreground hover:bg-muted hover:text-foreground"
                )}
              >
                <Icon className="size-4" />
                {label}
              </Link>
            )
          })}
        </nav>
      </aside>
      <div className="flex min-w-0 flex-col">
        <header className="flex h-14 items-center justify-between border-b px-6">
          <div className="text-sm text-muted-foreground">
            {isUnlocked ? "Vault unlocked" : "Vault locked"} ·{" "}
            {email ?? "anonymous"}
          </div>
          <div className="flex items-center gap-2">
            <Button variant="ghost" size="sm" onClick={handleLock}>
              <Lock className="size-4" />
              Lock
            </Button>
            <Button variant="ghost" size="sm" onClick={handleLogout}>
              <LogOut className="size-4" />
              Sign out
            </Button>
          </div>
        </header>
        <main className="min-w-0 flex-1 overflow-y-auto p-6">{children}</main>
      </div>
    </div>
  )
}

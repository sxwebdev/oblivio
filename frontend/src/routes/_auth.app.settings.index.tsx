import { createFileRoute } from "@tanstack/react-router"

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"

// Placeholder for Sprint 3 — TOTP, WebAuthn, sessions, audit and recovery
// management land in this section.
export const Route = createFileRoute("/_auth/app/settings/")({
  component: SettingsPage,
})

function SettingsPage() {
  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="text-sm text-muted-foreground">
          Account, security and recovery options.
        </p>
      </header>
      <Card>
        <CardHeader>
          <CardTitle>Coming in Sprint 3</CardTitle>
          <CardDescription>
            Two-factor (TOTP + Passkey), recovery code re-display, active
            sessions and password change.
          </CardDescription>
        </CardHeader>
        <CardContent />
      </Card>
    </div>
  )
}

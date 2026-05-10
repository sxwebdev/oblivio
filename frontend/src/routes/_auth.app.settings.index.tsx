import { Link, createFileRoute } from "@tanstack/react-router"
import { KeyRound, ShieldCheck } from "lucide-react"

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { buttonVariants } from "@/components/ui/button"

export const Route = createFileRoute("/_auth/app/settings/")({
  component: SettingsIndex,
})

function SettingsIndex() {
  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="text-sm text-muted-foreground">
          Account, security and recovery options.
        </p>
      </header>
      <div className="grid gap-4 sm:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldCheck className="size-5 text-primary" />
              Two-factor authentication
            </CardTitle>
            <CardDescription>
              Add an authenticator app or a passkey on top of your master password.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Link
              to="/app/settings/two-factor"
              className={buttonVariants({ variant: "outline" })}
            >
              Manage 2FA
            </Link>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <KeyRound className="size-5 text-primary" />
              Master password
            </CardTitle>
            <CardDescription>
              Change password and recovery code rotation land in Sprint 4.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              If you forget your password, restart from the sign-in screen and
              click <em>Recover</em>.
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

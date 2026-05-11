// Verify-email landing page. Reads ?token=... from the URL and calls
// AuthService.VerifyEmail. The token in the URL is single-use (server
// invalidates on consumption); we never display it back to the user.

import { useEffect, useState } from "react"
import { useNavigate, useSearch } from "@tanstack/react-router"

import { authClient } from "@/api/client"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"

type Status = "pending" | "ok" | "missing" | "error"

export default function VerifyEmailPage() {
  const navigate = useNavigate()
  // The route registers `token: string | undefined` as a search param.
  const search = useSearch({ from: "/_public/verify-email" }) as {
    token?: string
  }
  const [status, setStatus] = useState<Status>("pending")
  const [errorText, setErrorText] = useState<string>("")

  useEffect(() => {
    const tok = (search.token ?? "").trim()
    if (!tok) {
      setStatus("missing")
      return
    }
    void (async () => {
      try {
        await authClient.verifyEmail({ token: tok })
        setStatus("ok")
      } catch (e) {
        setStatus("error")
        setErrorText(e instanceof Error ? e.message : String(e))
      }
    })()
  }, [search.token])

  return (
    <div className="mx-auto mt-16 w-full max-w-md">
      <Card>
        <CardHeader>
          <CardTitle>Email verification</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4 text-sm">
          {status === "pending" && <p>Verifying your email…</p>}
          {status === "ok" && (
            <>
              <p>Thanks — your email is verified.</p>
              <Button onClick={() => navigate({ to: "/login" })}>
                Continue to sign in
              </Button>
            </>
          )}
          {status === "missing" && (
            <p className="text-destructive">No token in the link.</p>
          )}
          {status === "error" && (
            <>
              <p className="text-destructive">
                The link is invalid or expired. Request a new one from Settings
                → Security after signing in.
              </p>
              {errorText && (
                <p className="text-xs text-muted-foreground">{errorText}</p>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

// ConnectRPC clients wired with two interceptors:
//   1. bearerInterceptor   — injects `Authorization: Bearer <token>` from
//      the Zustand auth store on every authenticated procedure.
//   2. refreshOn401Interceptor — when a request fails with Unauthenticated
//      and we have a refresh token, calls AuthService.RefreshToken once,
//      updates the auth store, and retries the original RPC. On failure
//      (or if there's no refresh token) clears the session and lets the
//      caller redirect to /login. Multiple parallel 401s deduplicate
//      against a single in-flight refresh promise.

import {
  Code,
  ConnectError,
  createClient,
  type Interceptor,
  type Transport,
} from "@connectrpc/connect"
import { createConnectTransport } from "@connectrpc/connect-web"

import { AuthService } from "./gen/oblivio/v1/auth_pb"
import { VaultService } from "./gen/oblivio/v1/vault_pb"
import { ProjectsService } from "./gen/oblivio/v1/projects_pb"
import { EntriesService } from "./gen/oblivio/v1/entries_pb"
import { AuditService } from "./gen/oblivio/v1/audit_pb"
import { LoginTOTPService } from "./gen/oblivio/v1/login_totp_pb"
import { WebAuthnService } from "./gen/oblivio/v1/webauthn_pb"
import { SessionsService } from "./gen/oblivio/v1/sessions_pb"

import { useAuthStore } from "@/stores/auth"
import { useVaultStore } from "@/stores/vault"

// All ConnectRPC traffic is namespaced under `/api`. In dev the Vite
// proxy on :5173 forwards `/api/*` to the Go backend on :8080; in prod
// the WebUI is embedded and same-origin under the same `/api` prefix.
const baseUrl = "/api"

const bearerInterceptor: Interceptor = (next) => async (req) => {
  const token = useAuthStore.getState().accessToken
  if (token) {
    req.header.set("Authorization", `Bearer ${token}`)
  }
  return next(req)
}

// In-flight refresh promise. All concurrent 401s wait on the same
// promise so 5 parallel requests trigger ONE RefreshToken call.
let refreshInFlight: Promise<boolean> | null = null

// rawRefreshTransport is a no-interceptor transport used only by the
// refresh-on-401 interceptor to call AuthService.RefreshToken. Recursing
// through the interceptor stack would 401-loop on a failing refresh.
const rawRefreshTransport: Transport = createConnectTransport({ baseUrl })
const rawAuthClient = createClient(AuthService, rawRefreshTransport)

async function refreshTokens(): Promise<boolean> {
  const a = useAuthStore.getState()
  if (!a.refreshToken) return false
  try {
    const resp = await rawAuthClient.refreshToken({
      refreshToken: a.refreshToken,
      deviceInfo: { deviceId: a.deviceId, deviceType: "web" },
    })
    const p = resp.authPayload
    if (!p) return false
    a.setSession({
      userId: a.userId ?? "",
      email: a.email ?? "",
      accessToken: p.accessToken,
      refreshToken: p.refreshToken,
      accessExpiresAt: Number(p.accessExpiresAt?.seconds ?? 0n) * 1000,
      refreshExpiresAt: Number(p.refreshExpiresAt?.seconds ?? 0n) * 1000,
    })
    return true
  } catch {
    return false
  }
}

const refreshOn401Interceptor: Interceptor = (next) => async (req) => {
  try {
    return await next(req)
  } catch (e) {
    if (!(e instanceof ConnectError) || e.code !== Code.Unauthenticated) throw e
    // Don't try to refresh a failing refresh itself — bail to login.
    if (req.url.endsWith("/AuthService/RefreshToken")) {
      useAuthStore.getState().clear()
      useVaultStore.getState().lock()
      throw e
    }

    if (!refreshInFlight) {
      refreshInFlight = refreshTokens().finally(() => {
        refreshInFlight = null
      })
    }
    const ok = await refreshInFlight
    if (!ok) {
      useAuthStore.getState().clear()
      useVaultStore.getState().lock()
      throw e
    }
    // Replay with the freshly minted Bearer.
    const freshToken = useAuthStore.getState().accessToken
    if (freshToken) {
      req.header.set("Authorization", `Bearer ${freshToken}`)
    }
    return next(req)
  }
}

const transport = createConnectTransport({
  baseUrl,
  // Order: bearer first (so the inner refresh interceptor sees the
  // outgoing request with the current token), refresh wraps next() so
  // it catches Unauthenticated from the actual network call.
  interceptors: [bearerInterceptor, refreshOn401Interceptor],
})

export const authClient = createClient(AuthService, transport)
export const vaultClient = createClient(VaultService, transport)
export const projectsClient = createClient(ProjectsService, transport)
export const entriesClient = createClient(EntriesService, transport)
export const auditClient = createClient(AuditService, transport)
export const loginTotpClient = createClient(LoginTOTPService, transport)
export const webauthnClient = createClient(WebAuthnService, transport)
export const sessionsClient = createClient(SessionsService, transport)

// idempotencyHeaders returns a one-shot Idempotency-Key header dictionary.
// Pass it through to a mutating RPC via { headers: idempotencyHeaders() }.
// Each call generates a fresh UUID so retries by the user (e.g. double
// click on Save) collapse into a single server-side write.
export function idempotencyHeaders(): HeadersInit {
  return { "Idempotency-Key": crypto.randomUUID() }
}

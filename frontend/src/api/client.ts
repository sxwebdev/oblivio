// ConnectRPC clients wired with a Bearer-token interceptor backed by the
// Zustand auth store. Requests inherit `Authorization: Bearer <token>` for
// every authenticated procedure; anonymous ones are unaffected because the
// server-side allowlist accepts them with or without the header.

import { createClient, type Interceptor } from "@connectrpc/connect"
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

const transport = createConnectTransport({
  baseUrl,
  interceptors: [bearerInterceptor],
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

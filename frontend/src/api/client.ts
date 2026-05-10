// ConnectRPC client wired with a Bearer-token interceptor backed by the
// Zustand auth store. Requests inherit `Authorization: Bearer <token>` for
// every authenticated procedure; anonymous ones are unaffected because the
// server-side allowlist accepts them with or without the header.

import { createClient, type Interceptor } from "@connectrpc/connect";
import { createConnectTransport } from "@connectrpc/connect-web";

import { AuthService } from "./gen/oblivio/v1/auth_pb";
import { VaultService } from "./gen/oblivio/v1/vault_pb";

import { useAuthStore } from "@/stores/auth";

// In dev (vite on :5173), Vite's proxy forwards "/oblivio.v1.*" to the Go
// backend on :8080. In prod the WebUI is embedded and same-origin.
const baseUrl = "";

const bearerInterceptor: Interceptor = (next) => async (req) => {
  const token = useAuthStore.getState().accessToken;
  if (token) {
    req.header.set("Authorization", `Bearer ${token}`);
  }
  return next(req);
};

const transport = createConnectTransport({
  baseUrl,
  interceptors: [bearerInterceptor],
});

export const authClient = createClient(AuthService, transport);
export const vaultClient = createClient(VaultService, transport);

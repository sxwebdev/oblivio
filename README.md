<p align="center">
  <img src="screenshots/promo.webp" alt="Oblivio is a self-hosted, multi-user, zero-knowledge password manager" width="100%">
</p>

# OBLIVIO

Oblivio is a self-hosted, multi-user, **zero-knowledge** password manager
(server + WebUI). All sensitive material is encrypted on the client; the
server stores only ciphertext plus metadata and never sees plaintext
secrets, master passwords, vault keys, or item keys.

## Features

### Vault model

- **Projects** — logical groups of entries.
- **Entries** of multiple kinds (`login`, `totp`, `card`, `identity`,
  `ssh_key`, `note`) stored as a single typed table; the `encrypted_blob`
  contains kind-specific fields.
- **One account = one user.** No organisations, teams, sharing, or roles.
  Each user is an isolated vault.
- **TOTP (RFC 6238)** — either embedded in a `login` entry or as a
  standalone `totp` entry; codes are generated on the client.
- **Optimistic concurrency** via `expected_version` on update/delete.
- **Idempotency** for create/update via `Idempotency-Key` header
  (24 h TTL, scoped per user and procedure).
- **Real-time updates** via Server-Sent Events (SSE) backed by Postgres
  `LISTEN/NOTIFY`.

### Clients

- **WebUI** — React + Vite + Tailwind + shadcn, served from the same
  origin as the API (single binary, embedded static assets).
- **Crypto core** — isolated TypeScript package (`@oblivio/crypto`)
  used by the WebUI; the same primitives are mirrored in Go for round-trip
  testing, and can be reused by future mobile / desktop / browser-extension
  clients without changing the wire contract.

### Transport

- **ConnectRPC + Protobuf** (`buf`-generated stubs for Go and TS).
- **Bearer-only auth** — `Authorization: Bearer <token>`. No auth cookies,
  no implicit credentials, no CSRF surface.
- **Same-origin deployment** by default (static + API on one host);
  configurable CORS allow-list for split deployments.

## Security

### Zero-knowledge cryptography

- **Two-stage KDF.** `master_key = Argon2id(master_password, salt_user)`
  on the client; `auth_key = HKDF-SHA256(master_key, info="oblivio/auth/v1")`
  is what the client sends to authenticate. The server stores
  `Argon2id(auth_key)`; reversing it would require breaking two KDF
  layers.
- **Key hierarchy:** `master → vault → item`. A random per-user
  `vault_key` is wrapped under `master_key`; each entry has its own
  random `item_key` wrapped under `vault_key`.
- **Per-user Argon2id parameters** stored in the database, so the
  cost can be raised over time without re-hashing existing material.
- **Multi-thread Argon2id in the browser** when COOP/COEP/`crossOriginIsolated`
  are active; single-thread fallback otherwise.

### Encryption envelope

- **AES-256-GCM** via WebCrypto on the client and `crypto/aes` on the
  server. Envelope: `version(1) || nonce(12) || ciphertext || tag(16)`.
- **AAD binding** on every operation:
  - Items: `item_id || version || vault_id || "item"`.
  - Wrapped keys: `parent_id || child_id || version || "wrap"`.
  - Recovery wrap: `user_id || "recovery"`.
    Any swap, rollback, or re-parent attempt fails AEAD authentication.
- **Versioned crypto-protocol** (`crypto_protocol_version` in
  `system_state`, `vault_key_version` per user) enables stepped
  rollout of future algorithms.

### Authentication & sessions

- **Anti-enumeration** on `GetKDFParams`, `GetRecoveryParams`, and
  `Authorize`. Unknown emails get stable pseudo-parameters (HMAC of
  email + server secret) and a constant-time dummy Argon2id verify
  so timing cannot distinguish unknown vs. wrong-password.
- **Lockouts** on repeated authentication failures (`failed_attempts` +
  `locked_until`).
- **Sessions in Postgres** (`auth_sessions`), one row per user/device,
  with hashed access/refresh tokens, expiry, and revocation columns.
- **Refresh-token rotation with reuse detection** — replaying an old
  refresh token revokes the entire session and emits a metric.
- **JWT keys held in `memguard.LockedBuffer`** to resist swap/coredump
  leakage on the server.
- **Email verification** on registration with a single-use token.

### Two-factor authentication

- **TOTP (RFC 6238)** for sign-in.
  - The TOTP secret is encrypted by the **client** with
    `K_login_totp = HKDF(auth_key, "oblivio/login-totp/v1")` and only
    transiently decrypted on the server during a sign-in attempt.
  - The plaintext lives in a `memguard.LockedBuffer` and is destroyed
    immediately after verification.
  - A database-only attacker cannot derive the secret because it is
    sealed under a key the server does not store.
- **WebAuthn / Passkeys** (`github.com/go-webauthn/webauthn`).
  - **Origin-bound** — passkeys cannot be replayed against a phishing
    domain.
  - `UV=required` is enforced on registration, enable, and unlock
    ceremonies — authenticator possession alone never unlocks the
    vault.
  - `BackupEligible` / `BackupState` flag consistency is validated to
    detect cloned or migrated credentials.
- **Per-credential "Use to unlock" (PRF-based vault unlock).**
  Optional, off by default. Stores a _second_ wrapping of `vault_key`
  under a key derived from the WebAuthn **PRF extension** output. Useful
  but widens trust to whatever protects the authenticator (provider
  account, biometrics, hardware key + PIN). Users get an explicit
  warning before enabling and can revoke all unlock bundles in one
  click.

### Recovery

- One-time `recovery_code` generated by the **client** at registration
  and shown to the user exactly once (no automatic clipboard write).
- `recovery_key = Argon2id(recovery_code, recovery_salt)`; the server
  stores `recovery_wrapped_vault_key` and `Argon2id(recovery_proof)`.
- Recovery flow lets the user pick a new master password without
  re-encrypting every item — only the `vault_key` wrappers are
  rotated. All existing sessions are invalidated after a successful
  recovery.

### Server-side defense in depth

- **Postgres Row-Level Security** on `projects`, `entries`,
  `auth_sessions`, `user_webauthn_credentials`, `audit_log`, etc.
  Every authenticated request runs inside a transaction that issues
  `SET LOCAL app.current_user_id = $userID`; system jobs use a
  separate `app.bypass_rls = on` path. A repository that bypasses the
  interceptor sees an empty result set, not silent cross-tenant leakage.
- **Anonymous allow-list** — every ConnectRPC procedure is
  authenticated by default; only a hand-maintained list of public
  procedures (register, login, KDF params, recovery start, etc.) is
  exempt, and a test enforces it.
- **Rate limiting** per IP and per email on `Authorize`,
  `GetKDFParams`, `GetRecoveryParams`, `RecoveryStart`,
  `CompleteMFA`, etc.
- **Argon2id concurrency cap** (semaphore) so that login floods cannot
  exhaust memory and CPU.
- **Strict security headers** on every response, including static
  assets:
  - `Content-Security-Policy` with `default-src 'self'`, no
    third-party CDN, `frame-ancestors 'none'`, `object-src 'none'`,
    `base-uri 'none'`, `upgrade-insecure-requests`.
  - `Strict-Transport-Security` (HSTS preload-ready).
  - `Cross-Origin-Opener-Policy: same-origin`,
    `Cross-Origin-Embedder-Policy: require-corp`,
    `Cross-Origin-Resource-Policy: same-origin` —
    enables `crossOriginIsolated` for multi-thread Argon2id.
  - `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
    `Referrer-Policy: no-referrer`, `Permissions-Policy` locking down
    clipboard / interest-cohort, etc.
  - Snapshot tests pin the exact header strings so any weakening is a
    visible diff, not a silent regression.
- **TLS `verify-full`** to Postgres; production deployments expect TLS
  termination at the front edge.

### Audit log

- **Append-only** `audit_log` table with a **SHA-256 hash chain**:
  `self_hash[i] = SHA-256(prev_hash || canonical_json(row[i]))`.
- The current `audit_chain_head` is maintained in `system_state` under
  a row lock; a periodic background job recomputes the chain and
  alarms on mismatch.
- **External anchor (optional):** an Ed25519 signer (`LocalSigner` on
  disk by default; Vault Transit-ready) signs the chain head
  periodically, so tampering that rewrites both rows and the cached
  head is still detectable from outside the database.
- **Crypto-shred-aware events.** `account_delete` is appended only on
  successful deletion; every failed attempt emits
  `account_delete_attempt_failed` with a `stage`
  (`auth_key` / `totp` / `passkey`) and a `reason` in metadata. Probes
  are forensically visible without polluting the success record.
- Audit log is **read-only for the user** (via RLS); only the system
  role can insert.

### Client-side hardening (WebUI)

- **Auto-lock** on inactivity, on `visibilitychange`, and on
  `beforeunload` (synchronously zeroises `vault_key`).
- **Clipboard auto-clear** 30 seconds after copying a secret; clears
  only if the clipboard still contains the same value.
- **No `localStorage`/`IndexedDB` persistence** for keys — `vault_key`
  lives in a non-persisted Zustand store, in RAM only.
- **Redux DevTools disabled** in production builds; no inline scripts;
  no third-party CDN.
- **Best-effort zeroisation** of `Uint8Array` key material; `CryptoKey`
  objects are created with `extractable=false` where possible.

### Account deletion

- `DeleteMe` performs a **physical** cascade delete of the user,
  vault, projects, entries, sessions, WebAuthn credentials, and audit
  log. After the call, the server retains neither the ciphertext nor
  the wrapped `vault_key`.
- Honest caveat: database backups may still contain the encrypted
  material until their retention expires.

### Search

- **Blind-index lookup** (`HMAC-SHA256(K_blind, NFKC(lowercase(title)))`)
  for exact-match search over entry titles without exposing plaintext.
  `K_blind` is derived per user from `vault_key`. Full-text search is
  done on the client after decryption.

### Observability & operations

- **Prometheus metrics** for sign-in success/failure, refresh-token
  rotation, decryption events, rate-limit drops, etc.
- **Structured logs** that never contain plaintext secrets — only
  metadata (user id, action, IP, user agent).
- **Single-binary deployment.** The frontend is embedded via
  `//go:embed`, so a production install is one binary plus a Postgres
  connection.
- **Configuration via `xconfig`** with optional HashiCorp Vault for
  server-side secrets (JWT seeds, MFA KEK seed). Without Vault, the
  daemon falls back to a `secrets/` directory with mode `0600`.

## Usage

```text
NAME:
   oblivio - Oblivio service

USAGE:
   oblivio [global options] [command [command options]]

VERSION:
   version: local / revision: unknown / branch: unknown / pipeline ID: unknown / build date: unknown / go version: go1.26.3

COMMANDS:
   start       start the oblivio service
   config      configuration utilities
   migrations  database migration commands
   utils       custom cli utils
   version     print current version
   help, h     Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h     show help
   --version, -v  print the version
```

## Environment Variables

Environment variables [available here](ENVS.md).

## Security Policy

See [SECURITY.md](SECURITY.md) for the supported reporting channel,
coordinated-disclosure timing, threat model notes, and the full list of
hardening choices and their honest trade-offs.

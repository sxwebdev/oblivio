# Oblivio — implementation plan

A cloud, multi-user secrets manager. Server + WebUI (Go + React, with
zero-knowledge crypto on the client). High reliability bar: ZK model,
audit chain, memguard on the server, RLS as defence-in-depth.

---

## 1. Context

`oblivio` is a cloud, multi-user secrets manager: passwords, notes,
TOTP secrets, custom fields, organised by projects. Model: `server + WebUI`
(no TUI/GUI), later — mobile / desktop GUI / browser extension.

**What the user stores:**

- Projects (logical groups of entries).
- Entries belonging to a project. The entry kind (`entry_kind`) is one
  of `login`, `totp`, `card`, `identity`, `ssh_key`, `note`. Notes are
  simply `kind='note'` with a different set of fields in the
  `encrypted_blob`. There is no separate `notes` table.
- TOTP secrets (RFC 6238) — either a field on a `kind='login'` entry
  (`has_totp=true`) or a standalone `kind='totp'` entry.

**One account = one user.** No organisations, teams, sharing, or
RBAC roles. Every user is an isolated vault. If team vaults are needed
later, the architecture allows them, but the MVP does not implement them.

**Decisions confirmed by the user:**

| Branch                             | Choice                                           |
| ---------------------------------- | ------------------------------------------------ |
| Crypto model                       | Zero-knowledge (all crypto on the client)        |
| Encrypted-data storage             | Postgres only                                    |
| K_root for server-side secrets     | Admin secret + HashiCorp Vault                   |
| Master-password recovery           | Recovery code issued at registration             |
| Transport                          | ConnectRPC + buf (replacing the current gofiber) |
| Vault structure                    | One vault per user, projects live inside         |
| 2FA                                | TOTP + WebAuthn/Passkey from MVP                 |
| Existing leftovers in the skeleton | Full sweep before implementation                 |

**Target clients:** WebUI now, mobile / desktop GUI / browser extension
later. The architecture must let new clients plug in without changes to
the server contract.

---

## 2. Threat model

| Threat                                         | Mitigation                                                                                                                                                                                      |
| ---------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Disk / DB theft                                | All valuable data is encrypted with client-side keys; the server has no decryption keys                                                                                                         |
| Honest-but-curious server operator             | Same — even root access to Postgres yields no plaintext                                                                                                                                         |
| Active server breach + ciphertext substitution | AAD = `vault_id\|item_id\|version`; item version rotation; integrity log; client-side signature verification                                                                                    |
| Server-secret leak (Vault token, JWT keys)     | `memguard.LockedBuffer` in server RAM, Vault for root-of-trust, JWT key rotation                                                                                                                |
| Master-password brute force                    | Argon2id `t=3, m=128 MiB, p=4`; per-user salt; rate-limit on `/auth/kdf-params` and `/auth/login`                                                                                               |
| Password interception in TLS                   | TLS 1.3 only, HSTS preload, `verify-full` to Postgres                                                                                                                                           |
| WebUI XSS                                      | Strict CSP with Trusted Types, no inline scripts, no third-party CDN, lockfile lint, SRI                                                                                                        |
| Token / cookie theft                           | `__Host-` cookie, `HttpOnly`, `Secure`, `SameSite=Strict`; rotating refresh tokens; revoke on logout                                                                                            |
| Clipboard leak                                 | Auto-clear after 30 s, validates content before clearing                                                                                                                                        |
| Swap / coredump leak (server)                  | `memguard` for JWT keys and short-lived KDF-derived material; on the host — disable swap or enable swap encryption. The plaintext fed to `crypto/aes` still lands in regular heap — see §8.3    |
| Swap / coredump leak (Go desktop GUI)          | `memguard` for K_master / K_vault / K_item on desktop                                                                                                                                           |
| DevTools / Redux DevTools leak (Web)           | Decryption only on click "View" / "Copy"; Redux DevTools disabled in prod                                                                                                                       |
| Phishing / login replay                        | WebAuthn recommended as a mandatory second factor for prod accounts. UV (PIN/biometric) is not yet forced — see §17                                                                             |
| Auto-lock                                      | On inactivity (`visibilitychange` / timer), `beforeunload`, manual lock                                                                                                                         |
| Server tamper / rollback                       | Audit chain in Postgres (see §6.5); the head lives in `system_state` in the same DB — no external anchor implemented, see §17                                                                   |
| Honest-but-curious operator: TOTP login secret | Defence in depth: the secret is encrypted with a key derived from `auth_key`, which the server does not store. But during login the server sees the plaintext in RAM — that is not ZK, see §5.3 |

**Out of scope** (for the MVP, can be added later): supply-chain
attacks against our own NPM dependencies (mitigated via minimal deps +
lockfile lint + SBOM), and phishing fake clients (mitigated by
WebAuthn — origin binding).

---

## 3. High-level architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│ Web client (React + Vite + Tailwind + shadcn)                       │
│ + TanStack Router/Query + Zustand                                   │
│                                                                     │
│ Crypto core (isolated TS package @oblivio/crypto):                  │
│   • Argon2id WASM (multi-thread, COOP/COEP)                         │
│   • WebCrypto AES-GCM-256                                           │
│   • Key tree: master → vault → item                                 │
│   • TOTP RFC 6238                                                   │
│   • Blind index HMAC-SHA256                                         │
│                                                                     │
│ Sees plaintext only at the moment of use.                           │
└──────────────┬──────────────────────────────────────────────────────┘
               │ HTTPS + ConnectRPC (protobuf)
               │ Bearer access token + refresh token
               ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Oblivio Server (Go)                                                 │
│ — mx launcher (lifecycle, LIFO shutdown)                            │
│ — ConnectRPC handlers (AuthService, VaultService, …)                │
│ — connectrpc.com/authn middleware + rbacconnect                     │
│ — sxwebdev/tokenmanager: access (20 min) + refresh (30 days)        │
│ — Argon2id for the server-side hash of auth_key (two-stage KDF)     │
│ — memguard for JWT keys, Vault token, lockout state                 │
│ — Audit log writer (append-only, hash-chained)                      │
│ — Prometheus metrics, structured logs                               │
│                                                                     │
│ Stores: ciphertext, salt, kdf_params, verifier, hash(auth_key),     │
│         wrapped_recovery_key, project_blob, entry_blob, note_blob,  │
│         WebAuthn public keys, sessions, audit                       │
│                                                                     │
│ Does not see: master_password, master_key, vault_key, item_key,     │
│               field plaintexts, totp_secret, note plaintext         │
└──────┬──────────────────────────────────────┬───────────────────────┘
       │                                      │
       ▼                                      ▼
┌──────────────────┐                ┌──────────────────────────────┐
│ Postgres 18      │                │ HashiCorp Vault              │
│ TLS verify-full  │                │ (KV for admin_secret,        │
│ pgxpool          │                │  PKI for TLS, transit for    │
│ RLS enabled      │                │  signing JWT on rotation)    │
│ pgaudit          │                │ AppRole / Kubernetes auth    │
└──────────────────┘                └──────────────────────────────┘
```

**Postgres** is the only data store. The Pebble + TPM stub from the
current skeleton is removed: under ZK the server has no keys and cannot
decrypt ciphertext, and anti-tamper is solved by the append-only audit
chain in the same Postgres.

**Vault** handles only server-side secrets, never user data.

---

## 4. Cryptographic scheme (zero-knowledge)

### 4.1 Key lifecycle

```
master_password (browser only)
    │
    │ Argon2id(salt_user, kdf_params)         params per user from the DB
    ▼
master_key (32 bytes)
    │
    ├──► auth_key = HKDF-SHA256(master_key, info="oblivio/auth/v1", salt=email)
    │      │
    │      └──► sent to the server on login
    │           the server stores argon2id(auth_key) for verification
    │
    └──► AES-GCM unwrap
         │
         ▼
    vault_key (32 bytes, random, generated at registration)
         │
         ├──► AES-GCM unwrap (per entry)
         │     │
         │     ▼
         │   item_key (32 bytes per entry/note/project, random)
         │     │
         │     │ AES-GCM
         │     ▼
         │   field ciphertext (title, username, password, url, notes,
         │                     totp_secret, custom_fields)
         │
         └──► HMAC-SHA256 for the blind index (exact-match search by title)
```

**Two-stage KDF** (as in the Bitwarden web vault):

- `master_key` is used only for encryption and never leaves the client.
- `auth_key` is sent to the server on login and registration. The
  server stores `argon2id(auth_key)` — that is the server-side
  password, which does not let the server recover `master_password`
  (two KDF layers would have to be inverted).
- That is the classic ZK auth scheme without OPAQUE / aPAKE.

**Note on the HKDF salt.** In the implementation `auth_key` is derived
via `HKDF-SHA256(master_key, info="oblivio/auth/v1", salt=lowercase(email))`.
Email is a public, low-entropy value: the scheme works, but (a) HKDF
salt best practice is random, and (b) changing email requires
re-deriving `auth_key` and `auth_key_hash`. The target improvement is
to migrate the salt to a per-user `salt_user` (already stored in the
DB), so the email can change without re-authentication. See §17.

### 4.2 Argon2id parameters

| Layer                                 | t (iters) | m (KiB)          | p (threads)   |
| ------------------------------------- | --------- | ---------------- | ------------- |
| Client `master_key` (per-user, in DB) | 3         | 131072 (128 MiB) | 1 (see below) |
| Server `argon2(auth_key)`             | 3         | 131072 (128 MiB) | 4             |

Client KDF parameters live in `user_kdf_params` per user, so they can
be raised later without migrating millions of records. Server params
are pinned in code and versioned.

**Client parallelism.** Multi-thread Argon2id in the browser requires
COOP/COEP headers and `crossOriginIsolated`. On pages without isolation
the client is forced to `p=1` (single-thread). On devices with hard
memory limits (primarily iOS Safari, where a WASM instance can OOM at
128 MiB) a fallback to a smaller `m` is **not** implemented yet — a
user on an old iPhone may fail to log in. This is an open issue in
§17; the resolution is runtime device detection and per-device
parameters with a single shared `salt_user`.

**Server concurrency.** Every `Authorize` runs Argon2id with m=128 MiB.
Without a semaphore the server can OOM under a flood of anonymous
logins — that is a known DoS vector; the current mitigation is the
rate-limit middleware (see §7.4). A hard concurrency cap is planned
(see §17).

### 4.3 AEAD and AAD

- AEAD: **AES-256-GCM** via WebCrypto (native, constant-time).
- Nonce: 12 random bytes (CSPRNG); full envelope: `nonce(12) || ciphertext || tag(16)`.
- AAD for an item: `item_id || version || vault_id || "item"` —
  protects against swap and rollback attacks.
- AAD for a wrapped key: `parent_id || child_id || version || "wrap"`.
- AAD for the recovery wrap: `user_id || "recovery"`.

### 4.4 Blind index for title search

```
title_hash = HMAC-SHA256(K_blind, lowercase(NFKC(title)))
K_blind = HKDF-SHA256(vault_key, info="oblivio/blind/v1")
```

The `title_hash BYTEA` column is indexed by `(user_id, title_hash)`.
Exact match without plaintext. Full-text search is done on the client
after decrypting the list.

### 4.5 Recovery

At registration a `recovery_code` is generated (128 bits, base32 in a
format like `XXXX-XXXX-XXXX-XXXX-XXXX`). The client:

1. Derives `recovery_key = Argon2id(recovery_code, recovery_salt, params)`.
2. Encrypts `vault_key` with `recovery_key` → `recovery_wrapped_vault_key`.
3. Saves `recovery_salt` and `recovery_wrapped_vault_key` on the server.
4. Shows the recovery code to the user **exactly once** for manual
   copying (on a page warning that this is the last opportunity).
   Automatic clipboard copy is **not** done — the clipboard can be
   intercepted by extensions / processes, and the 30 s auto-clear
   window is excessive. The user must save the code outside the
   application (paper, another vendor's manager).

If the master password is lost, the user enters the recovery code,
gets `recovery_wrapped_vault_key + recovery_salt`, recovers
`vault_key`, picks a new `master_password`, re-encrypts only the
`wrapped_vault_key` (not the records themselves) and updates the
`verifier` + `auth_key_hash`.

### 4.6 Crypto-protocol versioning

Current envelope format: `nonce(12) || ciphertext || tag(16)`. **A
version byte inside the ciphertext envelope is not yet introduced** —
the format is unambiguously decoded by the current algorithm, and any
algorithm rotation will require either migrating every blob or
introducing a version byte with a decoder registry. This is a known
limitation: until the first real protocol upgrade
(XChaCha20-Poly1305 / post-quantum) there is no reason to add the
extra byte, but at the upgrade it must appear together with a
reader-side dispatcher (see §17).

Versioning outside the envelope already exists:
`user_vault.vault_key_version` and `system_state.crypto_protocol_version`
allow a stepped rollout.

---

## 5. Authentication and sessions

### 5.1 Registration

```
1. Client: user enters email + master_password.
2. Client: salt_user = randbytes(16); recovery_salt = randbytes(16).
3. Client: master_key = Argon2id(master_password, salt_user, kdf_params).
4. Client: auth_key = HKDF(master_key, "oblivio/auth/v1", email).
5. Client: vault_key = randbytes(32).
6. Client: wrapped_vault_key = AES-GCM(master_key, vault_key, AAD="vault-wrap").
7. Client: verifier = AES-GCM(master_key, "oblivio-verify").
8. Client: recovery_code = generate(); recovery_key = Argon2id(recovery_code, recovery_salt).
9. Client: recovery_wrapped_vault_key = AES-GCM(recovery_key, vault_key, AAD="recovery").
10. Client: POST AuthService.Register {
        email, salt_user, kdf_params, auth_key,
        verifier, wrapped_vault_key,
        recovery_salt, recovery_wrapped_vault_key,
    }
11. Server: argon2id(auth_key) → user_auth.password_hash; everything else is stored as-is.
12. Server: generates an email-verification token, sends the email.
13. Client: shows the recovery code once, requires confirmation.
```

What never goes to the server: `master_password`, `master_key`,
`vault_key`, `recovery_key`.

### 5.2 Login

```
1. POST AuthService.GetKDFParams { email } → { salt_user, kdf_params }
   • Anonymous endpoint, rate-limited per-IP AND per-email (5/min).
   • Returns stable pseudo-parameters for non-existent emails
     (defence against user enumeration).
2. Client: master_key = Argon2id(master_password, salt_user, kdf_params).
3. Client: auth_key = HKDF(master_key, "oblivio/auth/v1", email).
4. POST AuthService.Authorize { email, auth_key, totp_code? } → { challenge_for_2fa? | tokens }
   The server compares argon2id(auth_key) with user_auth.password_hash
   via subtle.ConstantTimeCompare. For a non-existent email the server
   still runs argon2id against a fixed dummy hash (lazily initialised
   on first use) to even out response time and close the timing-based
   user-enumeration channel on Authorize.
5. If 2FA is enabled the server requires TOTP / WebAuthn before issuing tokens.
6. On success the server returns:
   { access_token, refresh_token, expires_at, device_id,
     verifier, wrapped_vault_key }
7. Client: master_key.decrypt(verifier) == "oblivio-verify"? — sanity check.
8. Client: vault_key = master_key.decrypt(wrapped_vault_key).
9. Client: master_key is wiped (memguard / typed array fill 0 / GC hint).
10. Client: vault_key lives in the Zustand store **in RAM**, never persisted to localStorage/IndexedDB.
```

### 5.3 2FA: TOTP

- Secret: 20 bytes (160 bits).
- The TOTP secret is stored **encrypted** in the `entry_blob` of a
  user's special "auth" record OR as a field on the main record. The
  server does not see the plaintext secret.
- TOTP at login: the user types a code, the client validates it
  locally with `validateTOTP(secret, code)` — but that is useless for
  server-side verification.
- **So TOTP for login is server-side**: when 2FA is enabled the client
  encrypts `totp_secret` with `K_login_totp = HKDF(auth_key, "oblivio/login-totp/v1")`
  and sends it to the server. The server stores it — technically
  server-side, **but the secret is derived from `auth_key`, which the
  server cannot expand back into `master_password`**. At login the
  client sends `auth_key` → the server derives `K_login_totp` →
  decrypts the secret → validates the code. Right after the check
  `K_login_totp` is wiped from memguard.
- TOTP secrets **inside the vault** (for generating codes for any
  third-party services) are encrypted with the regular
  `vault_key/item_key` and decrypted only by the client — that is
  zero-knowledge.

**Honest assessment of the login-TOTP security model.** It is **not**
zero-knowledge: at login the server receives `auth_key`, derives
`K_login_totp`, decrypts `totp_secret`, and sees the plaintext in RAM
during the comparison. An honest-but-curious operator with process
access can grab it. The protection rests on two properties: (a) the
secret in the DB is encrypted with a key derived from `auth_key` — an
attacker with only a DB dump does not get the secret; (b) the
plaintext exists for a short time in a derived-key buffer (memguard)
and is wiped immediately. The alternative (client-side TOTP with
PAKE) is deferred. Do not market login-TOTP as a ZK feature.

**Gap with `ChangeMasterPassword` / `Recovery`.** `K_login_totp` is
derived from `auth_key`. When the master password (and therefore
`auth_key`) changes, the old `encrypted_secret` in `user_login_totp`
becomes undecryptable. The current `ChangeMasterPassword` and
`RecoveryComplete` handlers do not handle that — 2FA "silently
breaks" until setup is re-run. The target fix: the client decrypts
the old secret with its current `auth_key` before the change,
re-encrypts with the new `K_login_totp`, and passes the new value in
the rotation payload. See §17.

### 5.4 2FA: WebAuthn / Passkey

- Library: `github.com/go-webauthn/webauthn` on the server; the native
  browser API on the client.
- Origin binding protects against phishing.
- Registration: client → `Register Begin` → challenge →
  `navigator.credentials.create` → `Register Finish` with attestation
  → server stores `credential_id`, `public_key`, `sign_count` in
  `user_webauthn_credentials`.
- Authentication: after the initial `auth_key` check the server issues
  a WebAuthn challenge, the client → `navigator.credentials.get` →
  assertion → server validates the signature.
- WebAuthn is **only authentication** (proof of identity), not a
  source of decryption keys. `vault_key` still requires
  `master_password`.

**User Verification.** The RP config does not currently force
`UserVerification: required` — the library default ("preferred") is
in effect. That means a passkey without PIN/biometric is also
accepted, which is weaker than the stated model for a secret manager.
The target fix is `AuthenticatorSelection.UserVerification = required`
for Begin / Finish; see §17.

### 5.5 Recovery flow

```
1. POST AuthService.GetRecoveryParams { email } → { recovery_salt, kdf_params }
2. Client: recovery_key = Argon2id(recovery_code, recovery_salt, kdf_params).
3. POST AuthService.RecoveryStart { email, recovery_proof = HKDF(recovery_key, "auth/v1") }
   The server compares with argon2(recovery_proof) (stored separately).
4. Server returns recovery_wrapped_vault_key.
5. Client: vault_key = recovery_key.decrypt(recovery_wrapped_vault_key).
6. Client: user picks a new master_password.
7. Client: new master_key, new verifier, new wrapped_vault_key, new auth_key.
8. POST AuthService.RecoveryComplete with the new artefacts.
9. Server invalidates all sessions, requires re-login via WebAuthn (if it was enabled).
```

Recovery does not re-encrypt entries — only the `vault_key` wrap.
**Known incompleteness:** `user_login_totp.encrypted_secret` remains
encrypted under the old `K_login_totp` derived from the old
`auth_key`, so after recovery TOTP login is broken and requires a
re-setup. Same problem as §5.3, same fix: the client re-encrypts the
secret and passes it in `RecoveryComplete`.

### 5.6 Sessions

Implemented via the `goauth` skill: `tokenmanager.Manager[SessionData]`
× 2 (access + refresh), session store in Postgres (a separate
`auth_sessions` table). `SessionData` fields: `user_id, device_id,
device_type, device_name, ip, country, created_at`. By `device_id`
one device = one session; the user sees and can terminate them.

Refresh rotation: on `RefreshToken` the old pair is revoked and a new
one is issued. Reuse → error → invalidates the entire session.

**Token transport: Bearer only.** Auth middleware accepts tokens
exclusively from the `Authorization: Bearer <token>` header. Cookies
are not used for auth (initially planned as `__Host-Auth=`, but a
unified mechanism for web/mobile/extension was chosen instead). That
simplifies the CSRF model (`Authorization` is not sent automatically
by the browser), but requires the WebUI to keep the access token in
RAM (Zustand) and the refresh token in protected storage. Side
effect: if HttpOnly cookies become necessary later, explicit CSRF
protection (origin / sec-fetch-site check) will be needed.

---

## 6. Postgres schema

Every table (except `users` and `user_auth`) has
`user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE`.

### 6.1 Basics

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;       -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS citext;         -- case-insensitive email
```

### 6.2 Users and authentication

```sql
CREATE TABLE users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email               CITEXT UNIQUE NOT NULL,
    email_verified_at   TIMESTAMPTZ,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE user_kdf_params (
    user_id             UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    salt_user           BYTEA NOT NULL,
    argon2_t            INT  NOT NULL,
    argon2_m_kib        INT  NOT NULL,
    argon2_p            INT  NOT NULL,
    algo                TEXT NOT NULL DEFAULT 'argon2id'
);

CREATE TABLE user_auth (
    user_id             UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    -- argon2id(auth_key), PHC format
    auth_key_hash       TEXT NOT NULL,
    failed_attempts     INT  NOT NULL DEFAULT 0,
    locked_until        TIMESTAMPTZ
);

CREATE TABLE user_vault (
    user_id                       UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    verifier                      BYTEA NOT NULL,        -- AES-GCM(master_key, "oblivio-verify")
    wrapped_vault_key             BYTEA NOT NULL,        -- AES-GCM(master_key, vault_key)
    vault_key_version             INT   NOT NULL DEFAULT 1,
    -- recovery
    recovery_salt                 BYTEA NOT NULL,
    recovery_wrapped_vault_key    BYTEA NOT NULL,
    recovery_proof_hash           TEXT  NOT NULL,        -- argon2id(HKDF(recovery_key,"auth/v1"))
    recovery_used_at              TIMESTAMPTZ
);

CREATE TABLE user_login_totp (
    user_id             UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    -- AES-GCM(K_login_totp, totp_secret), where K_login_totp = HKDF(auth_key,"login-totp/v1")
    encrypted_secret    BYTEA NOT NULL,
    nonce               BYTEA NOT NULL,
    enabled             BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE user_webauthn_credentials (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name                TEXT NOT NULL,
    credential_id       BYTEA UNIQUE NOT NULL,
    public_key          BYTEA NOT NULL,
    aaguid              BYTEA,
    sign_count          BIGINT NOT NULL DEFAULT 0,
    transports          TEXT[],
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at        TIMESTAMPTZ
);
CREATE INDEX idx_webauthn_user_id ON user_webauthn_credentials(user_id);
```

### 6.3 Sessions

```sql
CREATE TABLE auth_sessions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id           TEXT NOT NULL,
    device_type         TEXT NOT NULL,         -- web, ios, android, desktop, extension
    device_name         TEXT,
    ip                  INET,
    country             TEXT,
    access_token_hash   BYTEA NOT NULL,        -- SHA-256(token); the raw token is not stored
    refresh_token_hash  BYTEA NOT NULL,
    access_expires_at   TIMESTAMPTZ NOT NULL,
    refresh_expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, device_id)
);
CREATE INDEX idx_sessions_refresh_hash ON auth_sessions(refresh_token_hash) WHERE revoked_at IS NULL;
CREATE INDEX idx_sessions_access_hash  ON auth_sessions(access_token_hash)  WHERE revoked_at IS NULL;
```

### 6.4 Vault, projects, entries, notes

```sql
CREATE TABLE projects (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- AES-GCM(item_key_project, JSON{name, description, color, icon}), AAD=project_id|version|vault|"project"
    encrypted_blob      BYTEA NOT NULL,
    wrapped_item_key    BYTEA NOT NULL,
    name_hash           BYTEA NOT NULL,
    version             INT  NOT NULL DEFAULT 1,
    sort_order          INT  NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_projects_user_id   ON projects(user_id);
CREATE INDEX idx_projects_name_hash ON projects(user_id, name_hash);

-- Notes are simply entries with kind='note' (a different field set inside encrypted_blob).
CREATE TYPE entry_kind AS ENUM ('login', 'totp', 'card', 'identity', 'ssh_key', 'note');

CREATE TABLE entries (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id          UUID REFERENCES projects(id) ON DELETE SET NULL,
    kind                entry_kind NOT NULL DEFAULT 'login',
    -- AES-GCM(item_key, JSON{title, username, password, url, notes_md, totp_secret, custom_fields…})
    encrypted_blob      BYTEA NOT NULL,
    wrapped_item_key    BYTEA NOT NULL,
    title_hash          BYTEA NOT NULL,
    -- list-view metadata WITHOUT plaintext (e.g. favicon-domain hash for login).
    -- Note: domain_hash is computed on the client from K_blind. The low cardinality
    -- of domains makes it vulnerable to a dictionary attack if K_blind ever leaks.
    domain_hash         BYTEA,
    has_totp            BOOLEAN NOT NULL DEFAULT FALSE,
    is_favorite         BOOLEAN NOT NULL DEFAULT FALSE,
    version             INT  NOT NULL DEFAULT 1,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_entries_user_id    ON entries(user_id);
CREATE INDEX idx_entries_project_id ON entries(project_id);
CREATE INDEX idx_entries_kind       ON entries(user_id, kind);
CREATE INDEX idx_entries_title_hash ON entries(user_id, title_hash);
CREATE INDEX idx_entries_updated_at ON entries(user_id, updated_at DESC);
```

### 6.5 Audit log

```sql
CREATE TYPE audit_action AS ENUM (
    'register','login','logout','refresh','password_change',
    'recovery_start','recovery_complete',
    'webauthn_register','webauthn_remove','totp_enable','totp_disable',
    'project_create','project_update','project_delete',
    'entry_create','entry_update','entry_view','entry_delete',
    'session_terminate'
);

CREATE TABLE audit_log (
    id                  BIGSERIAL PRIMARY KEY,
    user_id             UUID REFERENCES users(id) ON DELETE SET NULL,
    action              audit_action NOT NULL,
    target_id           UUID,
    ip                  INET,
    user_agent          TEXT,
    metadata            JSONB,
    -- Hash chain: prev_hash protects against admin row deletion
    prev_hash           BYTEA NOT NULL,
    self_hash           BYTEA NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_user_id    ON audit_log(user_id, created_at DESC);
CREATE INDEX idx_audit_action     ON audit_log(action, created_at DESC);
```

`self_hash = SHA-256(prev_hash || row_canonical_json)`. The genesis
`prev_hash` is 32 zero bytes, seeded by the first migration and stored
in `system_state` under the key `audit_chain_head`. The server
updates that value under a row lock after every write; a daily
background job recomputes the chain and compares it with the cached
head — alarms on mismatch.

**Threat-model limitation.** The head lives in the same Postgres as
the audit rows themselves. That defends against accidental corruption
and against an attacker who writes into `audit_log` bypassing the
application (RLS-bypass → strict check), but not against an adversary
with full DB access who recomputes the chain and overwrites the head.
An external anchor (S3 object lock / signed by a private key from
Vault transit / external transparency witness) is the target
improvement, not implemented. See §17.

### 6.6 System state and rate limiting

```sql
CREATE TABLE system_state (
    key                 TEXT PRIMARY KEY,
    value               JSONB NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Keys: 'audit_chain_head', 'jwt_keys_kid', 'crypto_protocol_version'.

CREATE TABLE rate_limit_buckets (
    bucket_key          TEXT PRIMARY KEY,        -- "auth_login:<email>", "kdf_params:<ip>", …
    tokens              REAL NOT NULL,
    last_refill_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

**Where the counters actually live.** The `rate_limit_buckets` table
exists in the schema, but the active rate limiter is in-memory
(token-bucket on `golang.org/x/time/rate`) — chosen in Sprint 4 to
avoid a DB round-trip on every anonymous request. Downside: counters
do not survive restarts and do not work in a multi-node deploy. The
table is left in place for a future migration to a shared store
(Postgres or Redis), see §17.

### 6.7 RLS as defence in depth

```sql
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY projects_owner ON projects
    USING (user_id = current_setting('app.current_user_id')::uuid);

-- Same for entries, user_webauthn_credentials, auth_sessions, audit_log.
```

**Invariant — mandatory transaction.** `SET LOCAL` only applies inside
a transaction, so every RLS-sensitive query **must** go through a
ConnectRPC interceptor, which opens a transaction per call, executes
`SET LOCAL app.current_user_id = $userID`, and puts the `pgx.Tx` into
the context. Repositories work with the tx from the context and never
call `pool.Query` directly against RLS tables. System operations
(without user scope) go through a separate wrapper that sets
`app.bypass_rls = on` in its own transaction. Reads of
`current_setting` use the missing_ok variant so an absent value
returns an empty string instead of raising.

### 6.8 Account deletion

All deletes are **physical**, no `deleted_at`.
`DELETE FROM users WHERE id = $1` cascades over the vault, projects,
entries, sessions, and the user's audit log. After the call the
server has neither the ciphertext nor the wrapped `vault_key` for
that user.

**Honest caveat about "crypto-shred".** This is not crypto-shred in
the strict sense: both `wrapped_vault_key` and the user ciphertext
remain in **Postgres backups**. Anyone who obtains a backup and knows
(or brute-forces) the user's `master_password` or `recovery_code`
recovers the data until the backup expires (typically 90 days). It is
"delete + wait for retention", not "destroy the key". Real
crypto-shred requires a per-user envelope key that physically lives
**outside** Postgres (e.g. in Vault transit) and is destroyed there
on `DeleteMe` — at which point even a fresh DB backup is unreadable
immediately. That model is the target improvement, see §17.

### 6.9 Migrations

`golang-migrate` via `iofs` (already wired in
`cmd/oblivio/start.go:152-168`). Files:

```text
sql/migrations/001_init_users_and_auth.up.sql   / .down.sql
sql/migrations/002_vault_and_sessions.up.sql    / .down.sql
sql/migrations/003_projects_and_entries.up.sql  / .down.sql
sql/migrations/004_audit_and_system.up.sql      / .down.sql
sql/migrations/005_rls_policies.up.sql          / .down.sql
sql/migrations/006_rate_limit.up.sql            / .down.sql
```

The existing 001–002 (`wallets`, `delegation_orders`, `settings`)
are removed entirely.

---

## 7. ConnectRPC API

### 7.1 Proto layout

```text
proto/
  buf.yaml
  buf.gen.yaml
  oblivio/v1/
    auth.proto             # AuthService
    vault.proto            # VaultService (verifier/wrapped_vault_key, password change)
    projects.proto         # ProjectsService
    entries.proto          # EntriesService (including kind='note')
    webauthn.proto         # WebAuthnService
    sessions.proto         # SessionsService (list + terminate)
    audit.proto            # AuditService (read-only for the user)
    common.proto           # Pagination, Cursor, Timestamp aliases
```

`buf.gen.yaml` produces:

- `internal/api/pb/**/*.connect.go`, `*.pb.go` (Go)
- `frontend/src/api/gen/**/*_pb.ts`, `*_connect.ts` (TS via `@bufbuild/protoc-gen-es`)

### 7.2 Services and methods (simplified, JSON for brevity)

```text
AuthService
  Register({email, salt_user, kdf_params, auth_key, verifier,
            wrapped_vault_key, recovery_salt, recovery_wrapped_vault_key,
            recovery_proof_hash}) → {user_id, email_verification_required}
  VerifyEmail({token}) → {}
  ResendVerification({email}) → {}                                  // anonymous, rate-limited
  GetKDFParams({email}) → {salt_user, kdf_params}                   // anonymous, rate-limited
  Authorize({email, auth_key, totp_code?, device_info}) →
        {auth_payload | mfa_challenge}
  CompleteWebAuthn({mfa_session_id, assertion}) → {auth_payload}
  RefreshToken({refresh_token, device_info}) → {auth_payload}
  Logout({}) → {}                                                   // requires auth
  ChangeMasterPassword({old_auth_key, new_auth_key, new_salt_user, new_kdf_params,
                        new_verifier, new_wrapped_vault_key}) → {}  // requires auth + reauth
  GetRecoveryParams({email}) → {recovery_salt, kdf_params}          // anonymous, rate-limited
  RecoveryStart({email, recovery_proof}) → {recovery_session_id, recovery_wrapped_vault_key}
  RecoveryComplete({recovery_session_id, new_master_password_artifacts…}) → {}

VaultService
  GetMyKeys() → {verifier, wrapped_vault_key, vault_key_version}
  GetMe() → {user, totp_enabled, webauthn_credentials_count, …}
  DeleteMe({reason?}) → {}                                          // crypto-shred

WebAuthnService
  RegisterBegin() → {challenge, options}
  RegisterFinish({attestation, name}) → {credential_id}
  ListCredentials() → {credentials[]}
  RemoveCredential({credential_id}) → {}

LoginTOTPService
  Setup({encrypted_secret, nonce}) → {}                             // ZK-encrypted, see 5.3
  Enable({totp_code}) → {}
  Disable({totp_code | webauthn_assertion}) → {}

ProjectsService
  List({pagination}) → {projects[]}
  Get({id}) → {project}
  Create({encrypted_blob, wrapped_item_key, name_hash, sort_order}) → {project}
  Update({id, expected_version, encrypted_blob, wrapped_item_key, name_hash}) → {project}
  Delete({id, expected_version}) → {}
  Reorder({ordered_ids[]}) → {}

EntriesService                                                     // including kind='note'
  List({project_id?, kind?, query_hashes?, cursor, limit}) → {entries_meta[], next}
  GetByIds({ids[]}) → {entries[]}                                  // includes encrypted_blob
  Create({project_id?, kind, encrypted_blob, wrapped_item_key,
          title_hash, domain_hash?, has_totp, is_favorite}) → {entry}
  Update({id, expected_version, …}) → {entry}
  Delete({id}) → {}
  ToggleFavorite({id, is_favorite}) → {}

SessionsService
  List() → {sessions[]}
  Terminate({session_id}) → {}
  TerminateAllExceptCurrent() → {}

AuditService
  List({pagination, action_filter?, from?, to?}) → {records[], next}
```

### 7.3 API authentication

In oblivio one account = one user, there is no role model. The
`rbacconnect` library is **not used**. A simple "authenticated user
required" authorisation with an explicit list of public procedures is
enough.

`internal/api/middleware/auth.go` — `connectrpc.com/authn.Middleware`:

1. Extracts the procedure name from the URL.
2. If the procedure is in the anonymous allow-list (`AuthService.Register`,
   `AuthService.VerifyEmail`, `AuthService.ResendVerification`,
   `AuthService.GetKDFParams`, `AuthService.Authorize`,
   `AuthService.CompleteWebAuthn`, `AuthService.RefreshToken`,
   `AuthService.GetRecoveryParams`, `AuthService.RecoveryStart`,
   `AuthService.RecoveryComplete`, healthcheck) — it passes through
   without authentication.
3. Otherwise it extracts the Bearer token, validates it via
   `tokenmanager.Manager[SessionData].Authenticate`, reads the user
   from `auth_sessions` + `users`, and puts `UserDataContext` into
   `context.Context`.
4. After the handler each repository runs
   `SET LOCAL app.current_user_id = $userID` — RLS provides isolation.

The anonymous allow-list lives as a constant in
`internal/api/middleware/auth.go` and is covered by a test asserting
that any new procedure requires Bearer by default.

### 7.4 Server-side endpoint protection

- **Rate limiting**: per-IP and per-email on `Authorize`,
  `GetKDFParams`, `GetRecoveryParams`, `RecoveryStart`. Implementation
  — in-memory token-bucket (`golang.org/x/time/rate`); single-node
  only, see §6.6 and §17.
- **Audit**: every mutation, plus `EntriesService.GetByIds` /
  `NotesService.GetByIds` (decryption is a critical event).
- **Idempotency**: `Idempotency-Key` header on entry `Create` /
  `Update`. Storage — the `idempotency_keys` table in Postgres, TTL
  24 h; the key is scoped per-user / per-procedure.
- **Optimistic concurrency**: `expected_version` on `Update` /
  `Delete`.
- **Prevent enumeration**: `GetKDFParams` returns stable
  pseudo-parameters for non-existent emails (HMAC of email +
  server-secret); `Authorize` runs argon2id against a fixed dummy
  hash for non-existent emails to even out response time.
- **Bot prevention**: optional hCaptcha / Turnstile on `Register` and
  `Authorize` (config flag). Without it, open registration is
  vulnerable to argon2-amplified DoS — recommended for any public
  deploy.

---

## 8. Server-side Go code

### 8.1 Layout

```
cmd/oblivio/                    main, version, start, migrations, config
internal/
  api/
    server.go                   ConnectRPC + HTTP mux + headers + CORS
    auth/
      auth_service.go
      kdf_helpers.go
      rate_limiter.go
    webauthn/
      webauthn_service.go
    projects/
      projects_service.go
    entries/
      entries_service.go        including kind='note'
    sessions/
      sessions_service.go
    audit/
      audit_service.go
    middleware/
      auth.go                   connectrpc.com/authn + anonymous allow-list
      audit_log.go              writes every mutation
      security_headers.go       CSP, COOP, COEP, HSTS, X-CT-O, Referrer-Policy
      idempotency.go
    pb/                         (gen) ConnectRPC stubs
  auth/
    manager.go                  tokenmanager wrapper per the goauth skill
    service.go                  Service[U IUser] generic
    argon2.go                   argon2id PHC encode/parse (forked from the current auth/password.go)
    sessions.go                 session repo + revoke + rotate
    secrets.go                  load/generate JWT keys, memguard.LockedBuffer
  audit/
    chain.go                    hash-chain helpers, verify job
    repo.go
  crypto/                       MINIMAL server-side set:
    aead.go                     AES-GCM helpers for encrypted_blob ops (NOT for decryption)
    hkdf.go                     HKDF-SHA256
    secure.go                   memguard wrappers (LockedBuffer, GetSlice, Destroy)
  config/
    config.go                   extend: AuthConfig, VaultConfig, RateLimitConfig, CORSConfig
    load.go
  store/                        pgxgen-generated repositories + extras
    repos/
      users/
      user_kdf_params/
      user_auth/
      user_vault/
      user_login_totp/
      user_webauthn_credentials/
      auth_sessions/
      projects/
      entries/
      audit_log/
      system_state/
      rate_limit_buckets/
    store.go                    aggregate
  jobs/
    service.go                  River queue (as today)
    audit_chain_verify.go       periodic: 1/day
    rate_limit_gc.go            periodic: 1/h
    sessions_gc.go              expired sessions cleanup
    pwned_password_check.go     (optional) HIBP API offline
  metrics/                      prometheus counters: login_success/_failure, refresh_*, etc.
proto/                          buf workspace
sql/
  migrations/
  queries/
  pgxgen.yaml
secrets/                        gitignored — (generated on first start if Vault is unavailable)
```

### 8.2 Existing-code sweep

**Delete entirely:**

- `internal/storage/` (Pebble + seal.go + users.go) — replaced by
  Postgres + the audit chain.
- `internal/tpm/` — the TPM stub is unused (Vault for the admin secret).
- `internal/keys/` — rewritten as `internal/auth/secrets.go`.
- `internal/api/server.go` (current gofiber) — replaced by ConnectRPC.
- `internal/store/repos/{wallets,delegation_orders,settings}/` — from
  another project.
- `sql/migrations/001_wallets_*`, `002_delegation_*` — replaced.
- `sql/queries/{wallets,delegation_orders,settings}/` — replaced.
- `internal/auth/totp.go` (server-side TOTP) — keep only for
  server-login-TOTP and rename to `internal/auth/login_totp.go`.

**Keep and reuse:**

- `cmd/oblivio/{main,start,migrations,config,version,utils}.go` — the
  CLI scaffolding and the mx-launcher.
- `internal/auth/password.go` — `HashPassword` / `VerifyPassword`
  helpers (Argon2id PHC); drop the bcrypt mention (none exists, all
  good), align parameters with §4.2.
- `internal/config/{config.go,load.go}` — extend AuthConfig /
  VaultConfig.
- `internal/jobs/service.go` — keep the River scaffolding, populate
  with new workers.
- `internal/metrics/metrics.go` — add new counters.
- `pkg/postgres/postgres.go` — unchanged.
- `embed.go`, `templates/`, `Makefile`, `dev/` — unchanged.

**Remove from `go.mod`:** `gofiber/v2`, `valyala/fasthttp`,
`goccy/go-yaml` (replaced by `xconfigyaml`), `shopspring/decimal`
(unnecessary for a non-money crypto project), `huandu/go-sqlbuilder`
(pgxgen is enough).

**Add to `go.mod`:**

- `connectrpc.com/connect`
- `connectrpc.com/authn`
- `github.com/sxwebdev/tokenmanager`
- `github.com/awnumar/memguard`
- `github.com/go-webauthn/webauthn`
- `github.com/sxwebdev/xutils` (if not already there)
- `golang.org/x/time/rate`

### 8.3 memguard in server code

Currently protected with `memguard.LockedBuffer`:

- JWT access signing key
- JWT refresh signing key
- The derived `K_login_totp` for the duration of one decryption
  operation (created, used, `Destroy()`'d immediately).

**What memguard does not protect.** The plaintext that the Go stdlib
`crypto/aes` accepts as input (or returns from `Open`) is a regular
heap `[]byte`, a copy in non-locked memory. Same for strings (`string`
is immutable and cannot be reliably zeroed). The MFA store (short-lived
challenge objects with `auth_key`) is currently not wrapped — the
justification: TTL ~10 minutes, in-memory store with no persistence.
The "memguard for everything critical" claim is **overstated**: the
protection is effective against swap / coredump at rest, not against
plaintext at the moment of use.

`memguard.CatchInterrupt()` wipes locked buffers on SIGINT/SIGTERM.

**Self-hosted without Vault.** If the env vars with access/refresh
seeds are empty, on first start the service generates random 32-byte
keys and writes them to `secrets.json` with mode 0600. The file is
stored **in plaintext** (base64). That is acceptable for single-node
dev and self deployments where disk access is OS-protected, but for
production it is recommended to inject the seeds from Vault via env
vars (`vault.enabled: true`). See §17.

### 8.4 mx launcher and start order

```go
lnc.ServicesRunner().Register(
    launcher.NewService(launcher.WithService(pg),         launcher.WithStartupPriority(1)),
    launcher.NewService(launcher.WithService(secrets),    launcher.WithStartupPriority(2)),
    launcher.NewService(launcher.WithService(jobService), launcher.WithStartupPriority(3)),
    launcher.NewService(launcher.WithService(apiServer),  launcher.WithStartupPriority(4)),
)
```

LIFO shutdown guarantees: API stops first, then jobs, then memguard
(destroy buffers), then Postgres.

### 8.5 Vault integration

`xconfig/sourcers/xconfigvault` is already present. Config:

```yaml
vault:
  address: https://vault.internal:8200
  auth:
    method: approle # approle | kubernetes | token
    role_id_path: /run/secrets/vault-role-id
    secret_id_path: /run/secrets/vault-secret-id
  paths:
    admin_secret: secret/data/oblivio/admin
    jwt_access_seed: secret/data/oblivio/jwt-access
    jwt_refresh_seed: secret/data/oblivio/jwt-refresh
```

At startup: fetch `admin_secret` and seeds, place them in
`memguard.LockedBuffer`, derive JWT keys via HKDF from the seed (so
they can be rotated without re-issuing).

Self-hosted scenario (no Vault): `secrets.json` in `data/` with mode
0600, generated on first start. Configuration: `vault.enabled: false`.

---

## 9. Client crypto library `@oblivio/crypto`

An isolated TypeScript package inside `frontend/packages/crypto/`.
Requirements:

- No dependencies other than `argon2-browser` (or our own WASM build of
  `argon2-cffi`) and native WebCrypto.
- 100% test coverage with Vitest (round-trip for every layer).
- Test vectors synchronised with `crypto/aead.go` on the server (for
  the Encrypt → server stores → Decrypt path-over-network case).
- Lockfile-lint and `npm audit --audit-level=high` block CI.

### 9.1 API

```typescript
// types.ts
export type Argon2Params = { t: number; m_kib: number; p: number };
export type WrappedKey = { ciphertext: Uint8Array; nonce: Uint8Array };
export type ItemEnvelope = {
  blob: Uint8Array; // nonce || ciphertext || tag
  wrapped_key: WrappedKey;
  aad: Uint8Array;
};

// kdf.ts
export async function deriveMasterKey(
  password: string,
  salt: Uint8Array,
  params: Argon2Params,
): Promise<CryptoKey>;
export async function deriveAuthKey(
  masterKey: CryptoKey,
  email: string,
): Promise<Uint8Array>;
export async function deriveBlindIndexKey(
  vaultKey: CryptoKey,
): Promise<CryptoKey>;
export async function deriveLoginTotpKey(
  authKey: Uint8Array,
): Promise<CryptoKey>;

// vault.ts
export async function generateVaultKey(): Promise<CryptoKey>;
export async function wrapVaultKey(
  masterKey: CryptoKey,
  vaultKey: CryptoKey,
): Promise<WrappedKey>;
export async function unwrapVaultKey(
  masterKey: CryptoKey,
  wrapped: WrappedKey,
): Promise<CryptoKey>;
export async function makeVerifier(masterKey: CryptoKey): Promise<Uint8Array>;
export async function checkVerifier(
  masterKey: CryptoKey,
  verifier: Uint8Array,
): Promise<boolean>;

// item.ts
export async function generateItemKey(): Promise<CryptoKey>;
export async function wrapItemKey(
  vaultKey: CryptoKey,
  itemKey: CryptoKey,
  aad: Uint8Array,
): Promise<WrappedKey>;
export async function unwrapItemKey(
  vaultKey: CryptoKey,
  wrapped: WrappedKey,
  aad: Uint8Array,
): Promise<CryptoKey>;
export async function encryptBlob(
  itemKey: CryptoKey,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array>;
export async function decryptBlob(
  itemKey: CryptoKey,
  blob: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array>;

// blind.ts
export async function blindIndex(
  blindKey: CryptoKey,
  value: string,
): Promise<Uint8Array>;

// totp.ts
export function generateTotpCode(secret: string, t?: Date): string; // RFC 6238
export function totpRemainingSeconds(period?: number, t?: Date): number;

// recovery.ts
export function generateRecoveryCode(): string; // 25 groups of 5 base32

// password-gen.ts
export function generatePassword(opts: GenOpts): string;
export function generatePassphrase(words: number): string; // EFF wordlist

// memory.ts (best-effort in the browser)
export function zeroize(view: Uint8Array): void; // fill with zeros
```

### 9.2 Multi-thread Argon2id

Requires HTTP headers from the server (static and API):

```
Cross-Origin-Opener-Policy:   same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
```

Otherwise — fall back to single-thread (i.e. `p=1` via the
`forceSingleThread` flag in `Argon2Params`).

### 9.3 Wiping sensitive data

`CryptoKey` cannot be reliably zeroed in WebCrypto (it lives in the
browser's context). Strategy:

- Keep the minimum amount of key material as `Uint8Array` (zeroed
  explicitly).
- Create `CryptoKey` with `extractable=false` where possible.
- On vault lock — set all references to null and ask the GC.
- Verify via DevTools that snapshots contain no plaintext fields.

---

## 10. Frontend (React + Vite + Tailwind 4 + shadcn)

### 10.1 Current state and plan

Already installed: React 19, Vite 8, Tailwind 4, shadcn-cli, base-ui.
Need to add:

- `@tanstack/react-router`, `@tanstack/react-query`
- `@bufbuild/connect-web`, `@bufbuild/protobuf`, `@connectrpc/connect-query`
- `zustand`, `zustand/middleware/persist`
- `argon2-browser` (or our own build)
- `@simplewebauthn/browser`
- `qrcode.react` (for TOTP registration)
- `react-hook-form`, `zod`
- `@oblivio/crypto` (local package)

`pnpm-workspace.yaml` is already created; add the package
`packages/crypto`.

### 10.2 `frontend/src` structure

```
frontend/
  packages/
    crypto/                       Isolated crypto package (see §9)
  src/
    api/
      gen/                        ConnectRPC TS stubs (buf)
      client.ts                   Transport + interceptor (Bearer + 401-retry)
    stores/
      auth.ts                     Zustand persist(session, deviceId)
      vault.ts                    Zustand NOT persist (vault_key, dirty caches)
      ui.ts
    routes/                       TanStack Router file-based
      __root.tsx
      _public/
        login.tsx
        register.tsx
        recover.tsx
        verify-email.tsx
      _auth/                      protected (redirect → /login if not auth)
        layout.tsx                + header, sidebar, lock UI
        index.tsx                 dashboard
        projects/
          index.tsx               list
          $projectId.tsx          detail
        entries/
          index.tsx               unified list with kind filter
          $entryId.tsx            detail (UI varies by kind: login / note / card / …)
          new.tsx                 create (kind chosen in the form)
        settings/
          security.tsx            password change, recovery code re-show, sessions
          two-factor.tsx          TOTP / WebAuthn
          audit-log.tsx
          danger.tsx              delete account
    components/
      ui/                         shadcn primitives
      forms/
      vault/
        EntryCard.tsx
        EntryForm.tsx
        TotpDisplay.tsx           live-updating
        PasswordField.tsx         show/hide + copy + auto-clear
        ProjectSelector.tsx
      auth/
        AutoLock.tsx              visibility/idle/blur listeners
        SessionList.tsx
    lib/
      crypto-context.tsx          React wrapper around @oblivio/crypto (vault_key in mem)
      query-client.ts
      utils.ts
    config/
      app-config.ts
    main.tsx
    App.tsx
```

### 10.3 Auto-lock and protection

- `<AutoLock />` mounted in `_auth/layout.tsx`.
- Idle timer (default 5 min, configurable).
- `document.visibilitychange` → starts a short timer (default 60 s).
- `window.beforeunload` → synchronously zeros `vault_key`.
- Any action that needs `vault_key` goes through the `useVaultKey()`
  hook — if nullable, redirects to a re-authentication screen with
  master_password (without a full logout).
- DevTools detection is not done (it is fiction), but in production
  builds `__REDUX_DEVTOOLS_EXTENSION__ = undefined`.

### 10.4 Clipboard auto-clear

```typescript
async function copySecret(text: string) {
  await navigator.clipboard.writeText(text);
  setTimeout(async () => {
    try {
      const cur = await navigator.clipboard.readText();
      if (cur === text) await navigator.clipboard.writeText("");
    } catch {
      /* permission denied */
    }
  }, 30_000);
}
```

### 10.5 Secure HTTP headers

The server sets on every response (including static):

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval';
                         style-src 'self' 'unsafe-inline'; img-src 'self' data:;
                         connect-src 'self'; frame-ancestors 'none'; base-uri 'none';
                         form-action 'self'; object-src 'none'; upgrade-insecure-requests
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload  (only if HSTS enabled in config)
Cross-Origin-Opener-Policy:   same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Permissions-Policy: clipboard-read=(self), clipboard-write=(self), interest-cohort=()
```

**Known relaxations relative to the ideal profile.**

- `style-src 'unsafe-inline'` — a starting compromise because inline
  styles are sometimes injected by Tailwind 4 / shadcn-runtime. The
  target fix is to drop `unsafe-inline` and switch to a static CSS
  bundle.
- `require-trusted-types-for 'script'` is **not yet set** —
  React/TanStack Router break without explicit trusted-types
  policies. The target fix is to add a policy in the frontend
  bootstrap and then enable the header.

A snapshot test on security headers pins the exact strings, so any
relaxation is a deliberate diff, not a silent regression.

### 10.6 Embedding the frontend

`embed.go` at the repo root (already present) — `//go:embed all:frontend/dist`.
In a production build the server serves static + ConnectRPC JSON on
the same origin. That eliminates CORS and simplifies CSP.

For development — Vite dev server on `:5173` with proxy `/api` → `:8080`.

---

## 11. Configuration and runtime

### 11.1 `config.yaml`

```yaml
log:
  level: debug
  format: console
  console_colored: true

server:
  addr: ":8080"
  tls:
    cert_file: /etc/oblivio/tls/cert.pem
    key_file: /etc/oblivio/tls/key.pem
  allowed_origins: ["https://oblivio.example.com"] # empty = same-origin only

postgres:
  host: localhost
  port: "5432"
  database: oblivio
  username: oblivio
  password: "" # from Vault or ENV
  ssl_mode: verify-full

auth:
  access_token_ttl: 20m
  refresh_token_ttl: 720h
  argon2_server:
    t: 3
    m_kib: 65536
    p: 1
  rate_limits:
    auth_login_per_email_per_min: 5
    auth_login_per_ip_per_min: 20
    kdf_params_per_ip_per_min: 30
    register_per_ip_per_hour: 5

webauthn:
  rp_id: oblivio.example.com
  rp_name: Oblivio
  rp_origin: https://oblivio.example.com

vault:
  enabled: true
  address: https://vault.internal:8200
  auth_method: approle
  role_id_path: /run/secrets/vault-role-id
  secret_id_path: /run/secrets/vault-secret-id

ops:
  metrics_addr: ":9090"
  pprof_enabled: false

jobs:
  audit_chain_verify_cron: "0 3 * * *"
  rate_limit_gc_interval: 1h
  sessions_gc_interval: 1h

email:
  provider: smtp # smtp | sendgrid | postmark
  from: no-reply@oblivio.example.com
  smtp:
    host: smtp.internal
    port: 587
    username: "" # from Vault
    password: "" # from Vault
```

`xconfig` is already wired in; `vault:"true"` tags for secrets work.

### 11.2 CLI commands

`cmd/oblivio/`:

- `oblivio start` — start the service (exists, fill in).
- `oblivio migrations up|down|status` — migrations (exists).
- `oblivio admin create-user --email …` — operational registration
  (with a pre-built artefact bundle from a client CLI).
- `oblivio version` — exists.
- `oblivio config print` — exists.

### 11.3 Docker / docker-compose

`dev/deploy/docker-compose.yml` — update for Postgres 18 + Vault
dev-mode + a volume for `secrets/`. Production Dockerfile —
distroless, multi-stage, `go build -trimpath -ldflags="-s -w"`.

---

## 12. Sprint roadmap

### Sprint 0 — Sweep and skeleton (1–2 days)

1. Delete files from §8.2 "Delete entirely".
2. Clean `go.mod`, `go.sum` (`go mod tidy`).
3. Drop `gofiber` from imports, replace `internal/api/server.go` with
   the ConnectRPC scaffolding.
4. Replace migrations 001–002 with an empty
   `001_init_users_and_auth.up.sql`.
5. `make build` green, `make migrate-up` green, `oblivio start` comes
   up without errors.
6. Verify: `curl http://localhost:8080/v1/health` (or
   `grpcurl localhost:8080 oblivio.v1.HealthService/Check`).

### Sprint 1 — Auth core (3–4 days)

1. proto `auth.proto`, `vault.proto`, `buf.gen`.
2. Migrations 001–002 (users, user_kdf_params, user_auth, user_vault,
   user_login_totp, auth_sessions).
3. pgxgen repositories for every table.
4. `internal/auth/manager.go` (tokenmanager wrapper).
5. `internal/api/auth/auth_service.go` — Register, GetKDFParams,
   Authorize, RefreshToken, Logout, GetMyKeys.
6. `connectrpc.com/authn` middleware, `rbacconnect` policy with
   anonymous allow.
7. memguard for JWT keys.
8. `@oblivio/crypto` package (kdf, vault, item, verifier, blind,
   recovery).
9. Frontend: TanStack Router routes `_public/*`, `_auth/*` skeleton;
   Zustand auth store; ConnectRPC client + interceptor.
10. Login + Register paths work end-to-end via the WebUI.
11. Verify: e2e test Register → Logout → Login → GetMe; round-trip
    `vault_key` through the server.

### Sprint 2 — Vault data (CRUD) (3–4 days)

1. Migrations 003–004 (projects, entries, audit_log, system_state,
   rate_limit_buckets).
2. proto + handlers for ProjectsService, EntriesService (including
   `kind='note'`), AuditService.
3. RLS policies (migration 005).
4. Idempotency middleware.
5. Frontend: pages `_auth/projects`, `_auth/entries` — list / detail
   / create / edit / delete. Notes in the UI = entries filtered by
   `kind='note'`.
6. Auto-refresh on create/edit via TanStack Query invalidation.
7. Blind-index search by title, client-side filtering by fields.
8. Auto-lock + clipboard auto-clear.
9. Verify: create / edit / view / delete; page reload requires
   unlock; tampering test (modify the blob in the DB via psql →
   client sees an AAD error).

### Sprint 3 — TOTP + WebAuthn + Recovery (3 days)

1. TOTP rendering for entries (live update every second).
2. proto + handlers `LoginTOTPService`, `WebAuthnService`.
3. `go-webauthn/webauthn` integration, migration for
   `user_webauthn_credentials`.
4. Frontend: `_auth/settings/two-factor` pages (enable/disable TOTP,
   register passkey).
5. Recovery flow: `recover.tsx`, `RecoveryStart`, `RecoveryComplete`.
6. Verify: e2e — add TOTP, log out, log in with TOTP; register a
   passkey, log out, log in with the passkey; forget the password →
   recover via the recovery code.

### Sprint 4 — Security and observability (2–3 days)

1. Rate-limiting middleware on sensitive endpoints.
2. Audit log writer + chain verify job.
3. CSP / COOP / COEP / HSTS headers in prod.
4. Prometheus metrics for login/refresh/decryption events.
5. Sessions UI (`_auth/settings/security`) + terminate.
6. Audit log UI (`_auth/settings/audit-log`).
7. Crypto-shred on account deletion.
8. Verify: rate-limit triggers; audit chain verify passes;
   CSP-violations do not break the legitimate flow.

### Sprint 5 — Polish, tests, deploy (2–3 days)

1. Vitest + Go test coverage > 80% for the crypto layers.
2. Round-trip tests Go ↔ TS (a shared test-vector file).
3. govulncheck, gosec, golangci-lint, npm audit, lockfile-lint in CI.
4. SBOM (cyclonedx-gomod).

---

## 13. Testing

Testing is a **first-class requirement**, not "later". Any PR that
lowers coverage on critical modules is blocked in CI. Goals and
mandatory test scenarios are spelled out below module by module.

### 13.1 What counts as a "critical module"

| Module                                                                                                 | Side   | Target coverage                | Why critical                                  |
| ------------------------------------------------------------------------------------------------------ | ------ | ------------------------------ | --------------------------------------------- |
| `packages/crypto` (TS): KDF, AEAD, vault/item-key wrap, blind index, TOTP, recovery code, password gen | client | ≥95%, branches ≥90%            | Any bug = silent corruption or leak           |
| `internal/auth/argon2` (PHC encode/parse, server-side hash auth_key)                                   | server | ≥95%                           | A PHC-parse bug = false-accept on login       |
| `internal/auth/manager` (tokenmanager wrapper, Authorize/Refresh/Logout)                               | server | ≥90%                           | Sessions are the system's trust anchor        |
| `internal/auth/sessions` (session store, rotate, revoke)                                               | server | ≥90%                           | Replay/reuse refresh = account takeover       |
| `internal/auth/secrets` (memguard load/zeroize/rotate)                                                 | server | ≥85%                           | JWT-key leak = forged sessions                |
| `internal/audit/chain` (hash-chain append + verify)                                                    | server | ≥95%                           | Tamper detect — the entire point of audit log |
| `internal/api/middleware/auth` (anonymous allow-list, Bearer extract, RLS-set)                         | server | ≥95%                           | Any bypass = full auth bypass                 |
| `internal/api/middleware/idempotency`                                                                  | server | ≥85%                           | Duplicate create entry                        |
| `internal/api/middleware/security_headers`                                                             | server | snapshot ≥100% (exact strings) | A CSP regression = real XSS                   |
| `internal/auth/login_totp` (server-side TOTP with derived key)                                         | server | ≥95%                           | 2FA bypass                                    |
| `internal/api/{auth,projects,entries,sessions,webauthn}` handlers                                      | server | happy + edge ≥80%              | API contract                                  |
| pgxgen repositories                                                                                    | server | basic CRUD + RLS-isolation     | Cross-user isolation                          |

Coverage is checked in CI: `go test -coverprofile`, `vitest run --coverage`.
Thresholds live in `Makefile` and the `pnpm test` script; they fail
when below.

### 13.2 Cross-language test vectors

`testdata/crypto-vectors.json` — a single source of truth for Go and
TS, run by both sides. Test vectors:

```json
{
  "argon2id": [
    {
      "password": "...",
      "salt_hex": "...",
      "t": 3,
      "m_kib": 131072,
      "p": 4,
      "hash_hex": "..."
    }
  ],
  "hkdf": [
    {
      "ikm_hex": "...",
      "info": "oblivio/auth/v1",
      "salt": "user@example.com",
      "out_hex": "..."
    }
  ],
  "aes_gcm": [
    {
      "key_hex": "...",
      "nonce_hex": "...",
      "aad_hex": "...",
      "plaintext_hex": "...",
      "ciphertext_hex": "..."
    }
  ],
  "verifier": [{ "master_key_hex": "...", "verifier_hex": "..." }],
  "blind_index": [
    { "vault_key_hex": "...", "title": "GitHub", "hash_hex": "..." }
  ],
  "totp_rfc6238": [
    {
      "secret_b32": "JBSWY3DPEHPK3PXP",
      "unix": 1234567890,
      "period": 30,
      "digits": 6,
      "code": "123456"
    }
  ],
  "recovery_wrap": [
    {
      "recovery_code": "AAAA-...",
      "salt_hex": "...",
      "vault_key_hex": "...",
      "wrapped_hex": "..."
    }
  ]
}
```

Go test: `internal/crypto/vectors_test.go`, TS test:
`packages/crypto/__tests__/vectors.test.ts` — both must produce
identical output.

### 13.3 Concrete scenarios for critical modules

**Crypto (TS + Go round-trip):**

- KDF: matches RFC 9106 reference vectors; per-user differing
  parameters; `forceSingleThread` fallback yields the correct result;
  empty password → error; invalid params → error.
- AEAD: successful seal/open; mutated ciphertext → `OperationError`;
  mutated AAD → `OperationError`; wrong nonce length → error; nonce
  reuse — must not occur, add a uniqueness test on 100k records.
- Wrap/unwrap of the key tree: master → vault → item full
  round-trip; wrong AAD → error; replay from another user_id → error
  (via AAD).
- Verifier: correct `master_key` passes; wrong → `false` without
  panic.
- Blind index: same title under one `vault_key` → same hash; different
  `vault_key` → different hash; NFKC normalisation (Unicode).
- TOTP: RFC 6238 vectors with SHA-1, period=30, digits=6,8.
- Recovery: code round-trip, wrong code → fail decrypt.
- Password gen: length and alphabet, no skew (chi-squared sanity).

**Auth manager:**

- Authorize: correct `auth_key` → token pair; wrong → error with the
  same message as for a non-existent email (anti-enumeration).
- Refresh: valid refresh → new pair, old revoked. Reuse old refresh
  → all sessions for that `user_id` revoked, metric increments.
- Logout: token passes verification, then `Authenticate` of the same
  tokens → error.
- Concurrency: 100 simultaneous Refreshes with the same refresh —
  exactly one succeeds.
- Lockout: after `failed_attempts >= N` in the interval →
  `locked_until` set; Authorize returns `RESOURCE_EXHAUSTED`.

**Sessions:**

- The `device_id` field is unique per user; re-authentication with
  the same `device_id` → reuses the row (no duplicate).
- TTL: after `access_expires_at` validation returns an error.
- `TerminateAllExceptCurrent` leaves only the current session.

**Audit chain:**

- Append works correctly:
  `self_hash[i] = SHA256(prev_hash || canonical(row[i]))`,
  `prev_hash[i+1] = self_hash[i]`.
- Verify job on a clean chain passes.
- Deleting any row / editing — verify fails pointing at the first
  broken row.
- JSON canonicalisation is stable: re-serialising yields identical
  bytes (sorted keys, no whitespace).

**Anonymous allow-list middleware:**

- Each public procedure from the list passes without Bearer.
- Any other (including future ones, added by a test scanning the
  full set of procedure names from `pb.*`) — without Bearer →
  `UNAUTHENTICATED`.
- Bearer with an expired token → `UNAUTHENTICATED`, not `INTERNAL`.
- After successful auth the context contains `user_id`, and that
  value really lands in `SET LOCAL app.current_user_id` (verified E2E
  via RLS).

**RLS isolation:**

- Two users A and B are brought up in the test; queries from A do
  not see or modify B's data even when trying `WHERE id = $idOfB`.

**Memguard secrets:**

- Load → `Bytes()` returns the expected; after `Destroy()` access
  panics.
- Rotation: new signatures pass, old ones remain valid until
  `expires_at`.

**Security headers:**

- Snapshot test: every expected header is present as the exact string.
- Every request (including 4xx, 5xx) carries CSP/COOP/COEP/HSTS.

### 13.4 Integration / E2E tests

- `cmd/oblivio start` comes up against a test DB
  (`postgres -c fsync=off` in testcontainers); E2E via the ConnectRPC
  TS client against the real server.
- Tamper test: after `Create` `UPDATE entries SET encrypted_blob[0] = 0x00`
  → `GetByIds` on the client fails with a decryption error.
- Cross-user tamper: an attempt to read someone else's entry by
  spoofing `id` → `NOT_FOUND` (RLS).
- Replay: reusing an old refresh → the entire session is revoked.
- Rate-limit: 6 failed Authorizes in a minute from one email → the
  7th returns `RESOURCE_EXHAUSTED`.
- Recovery: full recovery_code flow → new master_password → old
  master_password no longer works; all sessions invalidated.
- WebAuthn: register + authenticate against `go-webauthn/webauthn`
  virtual authenticator.
- Crypto-shred: `DeleteMe` → CASCADE removes the data; a `pg_dump`
  snapshot contains no rows for that `user_id`.

### 13.5 Security / supply chain

- `gosec` strict, `govulncheck` in CI per PR.
- `npm audit --audit-level=high` blocks merge.
- Lockfile-lint: `lockfile-lint --validate-https --validate-package-names`.
- `cyclonedx-gomod` SBOM generated at release.
- `cosign` signs the docker image (optional).
- `security.txt` under `/.well-known/security.txt`.
- Dependencies: GitHub Actions pinned by SHA; weekly `dependabot`
  PRs.

### 13.6 Performance / fuzz

- Fuzz test (Go 1.18+) on the PHC parser, AEAD wrappers, hash-chain
  canonical JSON.
- Bench for Argon2id with per-user params (regression control on
  login wall-clock).

---

## 14. Deployment

- One Postgres 18+ (`sslmode=verify-full`), TLS certificates from an
  internal CA or Let's Encrypt.
- HashiCorp Vault Agent on the same machine / sidecar.
- The server behind a TLS terminator (nginx / Cloudflare WAF).
- Postgres backups: `pgBackRest` or `wal-g`, S3 with Object Lock +
  Bucket Versioning + KMS.
- Logs to SIEM **without plaintext** (only metadata: user_id, action,
  IP, UA).
- Pre-launch checklist:
  - [ ] CSP/HSTS enabled and tested (Mozilla Observatory > A+).
  - [ ] hstspreload.org submission filed.
  - [ ] External crypto audit (Cure53 / Trail of Bits / Doyensec).
  - [ ] Bug bounty programme published.
  - [ ] Backup restore drill performed at least once.

---

## 15. Critical-files checklist (for execution)

**Delete:**

- `internal/storage/{seal.go,storage.go,users.go}`
- `internal/tpm/tpm.go`
- `internal/keys/keys.go`
- `internal/api/server.go` (current gofiber)
- `internal/store/repos/{wallets,delegation_orders,settings}/`
- `sql/migrations/001_wallets_*.{up,down}.sql`
- `sql/migrations/002_delegation_*.{up,down}.sql`
- `sql/queries/{wallets,delegation_orders,settings}/`
- `internal/models/models_gen.go` (regenerated by pgxgen)

**Replace entirely:**

- `internal/auth/totp.go` → `internal/auth/login_totp.go` (server-side
  TOTP with derived key)
- `cmd/oblivio/start.go` (uncomment + rewrite onto ConnectRPC)
- `config.yaml` (see §11.1)

**Create new:**

- `proto/oblivio/v1/*.proto` + `buf.yaml` + `buf.gen.yaml`
- `sql/migrations/00{1..6}_*.{up,down}.sql`
- `sql/queries/{users,user_kdf_params,user_auth,user_vault,user_login_totp,user_webauthn_credentials,auth_sessions,projects,entries,audit_log,system_state,rate_limit_buckets}/*.sql`
- `internal/api/{server.go,auth/,webauthn/,projects/,entries/,sessions/,audit/,middleware/}`
- `internal/auth/{manager.go,service.go,sessions.go,secrets.go,argon2.go,login_totp.go}`
- `internal/audit/{chain.go,repo.go}`
- `internal/crypto/{aead.go,hkdf.go,secure.go}` (minimal; main crypto
  is on the client)
- `frontend/packages/crypto/` (a new workspace package)
- `frontend/src/{api,stores,routes,components,lib}/...`

**Unchanged:**

- `cmd/oblivio/{main,version,migrations,utils,config}.go`
- `internal/config/{config.go,load.go}` (extend, not delete)
- `internal/jobs/service.go` (populate, keep the scaffolding)
- `internal/metrics/metrics.go`
- `pkg/postgres/postgres.go`
- `embed.go`, `templates/`, `Makefile`, `dev/`

---

## 16. Verification (how to check the finished service end-to-end)

1. `make build && make migrate-up && oblivio start` — service comes
   up, healthcheck responds.
2. `pnpm --filter frontend dev` (via Vite) OR open `https://localhost:8080`.
3. Registration: create a user, get a recovery code, confirm email.
4. Enable TOTP, add a passkey.
5. Logout / login: repeat with TOTP, repeat with the passkey (no
   TOTP).
6. Create a project, add an entry with a TOTP secret, confirm the
   TOTP code refreshes.
7. Create a note.
8. Via psql: `SELECT encrypted_blob FROM entries LIMIT 1` — must be a
   random noise-like byte string.
9. Via psql: `UPDATE entries SET encrypted_blob = '\\x00...' WHERE id = …`
   — the client on read must show an integrity error.
10. Logout all sessions from another device; the current one stays.
11. Forgot-password flow: enter recovery code, set a new
    master_password, sign in again.
12. Delete the account: data disappears from the DB, backups become
    unreadable (after rotation).
13. `curl -X POST https://localhost:8080/oblivio.v1.AuthService/Authorize`
    six times with a wrong password in a minute — the sixth returns
    `RESOURCE_EXHAUSTED`.
14. `make test`, `pnpm test`, `govulncheck ./...`,
    `npm audit --audit-level=high` — all green.
15. Mozilla Observatory grade ≥ A+ in prod.

---

## 17. Known limitations and target improvements

This section exists so that the current implementation is described
honestly. Each item is a deliberate compromise or unfinished work,
**not** a forgotten piece. Users and reviewers should see the honest
picture before trusting the data.

### 17.1 Crypto model and key material

- **Login-TOTP is not zero-knowledge.** The server sees the TOTP
  secret plaintext for one operation during login (decrypted with a
  key derived from `auth_key`). The plaintext is now returned from
  crypto helpers as a `*memguard.LockedBuffer` and zeroised via
  `defer Destroy()`, but it is still an in-process trick, not a real
  ZK model. Client-side TOTP with PAKE is deferred.
- **Crypto-shred is not cryptographic.** On `DeleteMe` the row is
  cascaded out, but both the key wrap and the ciphertext remain in
  DB backups until retention expires. Effectively stale until backup
  rotation. The target model — a per-user envelope key in Vault
  transit — is deferred.

### 17.2 Metadata and side channels

- **`domain_hash` low cardinality.** A per-user `blind_pepper` is now
  required (HKDF salt when deriving `K_blind`), but if `K_blind`
  leaks, a dictionary of popular domains within that specific user
  still works. The radical fix — drop `domain_hash` in favour of
  client-side favicons — is deferred.

### 17.3 Operational

- **CSP `style-src 'unsafe-inline'`.** Tailwind 4 in production does
  not inject inline styles — `unsafe-inline` could be removed
  immediately. Not done in this iteration.
- **CAPTCHA on `Register` not enforced.** The Argon2id concurrency
  cap removes the main DoS vector, but automated registration is
  still possible. hCaptcha / Turnstile via a config flag is an
  operator-side task.
- **MFA KEK with per-instance fallback.** Without
  `OBLIVIO_MFA_KEK_SEED` each instance generates its own KEK; a
  multi-instance deploy loses cross-instance challenge resolution and
  needs sticky session on the LB. With a seed — everything works
  transparently via HKDF.
- **The pre-launch checklist remains manual.** External crypto audit,
  hstspreload, bug bounty, restore drill — team tasks, not code.

---

## 18. Open questions (can be deferred)

- **Sharing entries** between users (team password manager) — **out
  of MVP scope**. In the MVP, one account = one user, no sharing or
  RBAC. If needed later: implemented via X25519 public keys in
  `users` and re-wrapping `item_key`.
- **File attachments** to entries — post-MVP, a separate store (S3 /
  on-disk) with ZK AES-GCM-stream encryption.
- **Browser extension** — a separate workspace package `extension/`
  reusing `@oblivio/crypto`. Manifest v3 — service worker + content
  scripts + popup.
- **Mobile** (React Native / Expo) — reuse `@oblivio/crypto` via
  react-native-quick-crypto + WASM-Argon2.
- **Desktop GUI** (Wails / Tauri) — native Go + memguard + the
  system keychain for the refresh token.
- **Import from Bitwarden / 1Password / KeePass** — post-MVP, a
  separate CLI tool that reads the export on the client, encrypts,
  and uploads via the API.

These items are documented so that the architecture does not block
adding them later.

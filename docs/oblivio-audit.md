# Audit Report — Oblivio (zero-knowledge password manager)

**Audit performed against commit `3d34895` on branch `init-repo`.**
Scope: server-side Go (`internal/**`, `cmd/oblivio`), client-side crypto
(`frontend/packages/crypto/src/**`), migrations, and the project
architecture from `docs/oblivio.md`.

---

## 1. Top 5 critical issues

### 1.1. The recovery code is never rotated — a permanent backdoor to `vault_key`

**Where:** [sql/queries/user_vault/user_vault.sql:17-27](../sql/queries/user_vault/user_vault.sql#L17-L27), and the explicit comment in the same query:

> "The recovery-related material (salt + wrapped) stays put so the same recovery code can still be used (the client should generate a new one after a successful recovery, but that is a UX nicety — not enforced)."

`CompleteRecovery` updates `verifier`, `wrapped_vault_key`, and `vault_key_version`, but **does not touch** `recovery_salt`, `recovery_wrapped_vault_key`, or `recovery_proof_hash`. The same goes for `ChangeMasterPassword` — see [internal/api/auth/service.go:724-730](../internal/api/auth/service.go#L724-L730).

`vault_key` is not rotated on recovery (only re-wrapped under the new `master_key`). So `recovery_wrapped_vault_key = AES-GCM(recovery_key, vault_key)` stays valid forever under the same `recovery_code`.

**Exploitation.** A user registers in 2025, stores their recovery code in a cloud note. In 2027 they change their master password five times and go through a recovery. In 2028 an attacker gets hold of the old note — they now hold a **current** recovery code that grants access to the entire current vault. The audit log shows no signs of compromise (the recovery flow was never previously triggered by the attacker).

The architecture document §17 **does not record** this gap. It violates forward secrecy for the recovery channel.

**How to fix.**

1. In `RecoveryComplete`, require the client to send new `recovery_salt`, `recovery_wrapped_vault_key`, and `recovery_proof_hash` (the client generates a fresh recovery code, displays it to the user, and re-encrypts the current `vault_key`). Do the same for `ChangeMasterPassword` (optionally, behind a UI flag).
2. A stronger alternative: rotate the `vault_key` itself on recovery (and re-wrap every `wrapped_item_key` under the new `vault_key` — expensive but semantically correct).
3. Minimum bar: clear `recovery_used_at` after a recovery and require an explicit `RegenerateRecoveryCode` call before `recovery_proof_hash` becomes valid again.

**Severity:** High. This contradicts the entire zero-knowledge narrative.

---

### 1.2. The audit anchor isn't checked on a "clean" pass — tamper protection is a façade

**Where:** [internal/jobs/audit_chain_verify.go:62-86](../internal/jobs/audit_chain_verify.go#L62-L86)

```go
if res.OK() {
    // ...
    return nil  // ← anchor is NOT checked
}
// only on chain MISMATCH:
if err := w.verifyAnchor(ctx, res.Head); err != nil { ... }
```

The worker's logic: if the SHA-256 chain matches `system_state.audit_chain_head`, exit without verifying the anchor. The anchor is checked **only** when the chain has already diverged.

But the anchor's whole point is to catch an attacker who **consistently** rewrote both the `audit_log` rows _and_ `audit_chain_head`. In that scenario:

- chain hash == stored_head → `res.OK() == true` → we exit.
- The anchor is never consulted.
- The attacker has fully covered their tracks.

This is exactly the attack the anchor was supposed to defend against. The current implementation only catches incoherent edits (which the old chain without an anchor would have caught too).

Additionally, [internal/audit/verify.go:67-119](../internal/audit/verify.go#L67-L119): the anchor does not capture a high-water mark — `audit_chain_anchors` stores only `head`, without the `audit_log.id` it was signed up to. So even fixed logic cannot distinguish "we legitimately moved forward past the anchor" from "history was rewritten".

**Exploitation (model: internal operator / DBA, or RCE on the DB host).**

1. Get SQL access to `audit_log` and `system_state`.
2. Delete or alter the last N rows (for example, the `entry_view` row for the user's bank password).
3. Recompute `self_hash` for the remaining rows.
4. Write a new `audit_chain_head`.
5. The next audit-verify run: chain matches, OK, anchor never consulted. Tampering is not detected.

**How to fix.**

1. `AuditChainAnchorWorker.Work` should record `(head, last_audit_id, signature, signer_id)` — pinning the anchor's height.
2. `AuditChainVerifyWorker.Work` should **always** load the latest anchor and:
   - Recompute the chain up to `last_audit_id` (in batches) and compare with `anchor.head`.
   - If `current_head != anchor.head`, still verify that rows `[1..anchor.last_audit_id]` produce `anchor.head` (i.e. history up to the signing moment is unchanged; moving forward from there is allowed).
   - Verify `ed25519.Verify(pub, anchor.head || anchor.last_audit_id, anchor.signature)` — the id must be covered by the signature.
3. Alarm on: signature invalid; `anchor.head != computed_hash_at_anchor_height`.

**Severity:** High. The protection is advertised as defence against a DB-only attacker; right now it does not work.

---

### 1.3. Permanent account lockout DoS — five failed attempts never reset `failed_attempts`

**Where:** [sql/queries/user_auth/user_auth.sql:12-20](../sql/queries/user_auth/user_auth.sql#L12-L20)

```sql
SET failed_attempts = failed_attempts + 1,
    locked_until    = CASE
        WHEN failed_attempts + 1 >= 5 THEN now() + interval '15 minutes'
        ELSE locked_until
    END
```

`failed_attempts` is reset **only** in `ResetFailedLogin` (called on a successful login) or `UpsertUserAuth` (recovery / change password). The counter itself never decreases with time.

**Permanent-lockout scenario.** The attacker knows the victim's email.

1. Sends 5 wrong-password `Authorize` calls → `failed_attempts=5`, lockout 15 min.
2. The victim waits 15 minutes — can they log in? No: the attacker sends one more wrong-password every 15 min. The condition `failed_attempts(6) + 1 >= 5` is always true → `locked_until = now + 15min`. Every wrong-password extends the lockout until the victim manages a successful login. The victim cannot manage a successful login, because `locked_until.After(time.Now())` is always true.

The per-email rate limit (5/min for `Authorize` in `rate_limit.go`) **does not help** — the attacker needs one attempt every 15 minutes (1/900 RPS), which is far below any rate limit.

**Attack cost:** one HTTP request every 15 minutes permanently locks the chosen email.

**How to fix.**

1. Reset `failed_attempts` when `locked_until IS NOT NULL AND locked_until < now()`:

   ```sql
   SET failed_attempts = CASE
       WHEN locked_until IS NOT NULL AND locked_until < now() THEN 1
       ELSE failed_attempts + 1
   END,
   locked_until = CASE
       WHEN (CASE WHEN locked_until IS NOT NULL AND locked_until < now()
                  THEN 1 ELSE failed_attempts + 1 END) >= 5
       THEN now() + interval '15 minutes'
       ELSE NULL
   END
   ```

2. Additionally: give `failed_attempts` a TTL (e.g. a 1 h sliding window) or use exponential backoff (`5min, 15min, 1h, 4h, capped`).
3. More broadly, account-level lockout as an unauthenticated-DoS blocker is an antipattern. The better option is per-IP + per-email rate limiting + CAPTCHA after N failures, without blocking the account itself.

**Severity:** High (DoS vector against a specifically chosen user).

---

### 1.4. `dummyAuthHash` uses the wrong Argon2 parameters — user enumeration via timing

**Where:** [internal/api/auth/service.go:1147-1166](../internal/api/auth/service.go#L1147-L1166)

```go
h, err := auth.HashAuthKey(seed, auth.Argon2Params{T: 3, MKiB: 65536, P: 1})
```

The dummy hash is computed with `m=64 MiB, p=1`. A real user stores PHC with parameters `s.argon2 = {T:3, MKiB:131072, P:4}` (from the `Argon2Server` config). On `VerifyAuthKey` the parameters are taken from the PHC string → the real verify takes ~100–200 ms (128 MiB, 4 threads), while the dummy verify takes ~30–50 ms (64 MiB, 1 thread).

A 50–150 ms gap across the TLS boundary is measurable at N≥30 requests. This **reintroduces** the user-enumeration timing channel that the `dummyAuthHash` anti-enumeration branch was supposed to close.

In addition:

- For a non-existent email, `Authorize` skips `GetUserAuth` + the lockout check (one DB round-trip = another ~3–10 ms of difference).
- For a locked account, `Authorize` returns **instantly** before `VerifyAuthKey` — locked vs. unknown vs. unlocked are trivially distinguishable.

**How to fix.**

1. Compute `dummyAuthHash` lazily with **the same** parameters as `s.argon2`. Better still — pass it into `NewService` and keep it in the struct.
2. On the locked branch, still call `auth.VerifyAuthKey(authKey, dummyAuthHash())` (or sleep to the common wall-clock total).
3. On the unknown-email branch, even out the DB round-trip: do an empty `SELECT 1`, or skip the lookup and go straight to the dummy verify.

**Severity:** Medium-High. You explicitly stated an anti-enumeration goal, and three separate side channels defeat it.

---

### 1.5. `rotateLoginTOTPInTx` silently drops TOTP on partial input

**Where:** [internal/api/auth/service.go:986-1012](../internal/api/auth/service.go#L986-L1012)

```go
if len(newEncrypted) > 0 && len(newNonce) > 0 {
    return repo.UpsertUserLoginTOTP(...)
}
// Empty bytes → drop the row if it exists.
return repo.DeleteUserLoginTOTP(ctx, userID)
```

If the client sends `newEncrypted != ""` but `newNonce == ""` (or vice versa) due to any bug — both should be either non-empty or empty — the code silently falls into `DELETE`. The user's **second factor silently disappears**, and the operation was not initiated by them, but by their client during `ChangeMasterPassword` / `RecoveryComplete`.

Additionally: the `user_login_totp` schema stores `nonce` as a separate column. But `OpenLoginTOTPSecret` ([internal/auth/login_totp.go:67-80](../internal/auth/login_totp.go#L67-L80)) and `AESGCMOpen` ([internal/crypto/aead.go:31-56](../internal/crypto/aead.go#L31-L56)) expect the envelope `version(1) || nonce(12) || ct+tag` — the nonce is **already inside** `encrypted_secret`. The `nonce` column is dead, never read for decryption.

This means:

- The fact that `rotateLoginTOTPInTx` splits `newEncrypted` and `newNonce` is an artifact of an outdated schema.
- On the client side, during `ChangeMasterPassword` / `RecoveryComplete`, both fields must be kept in sync — an extra invariant that is easy to violate.

**How to fix.**

1. Drop the `user_login_totp.nonce` column (down migration: keep; migration: ignore).
2. Remove `nonce` from `Setup` / `Enable` / `Disable` / `RotateLoginTOTP` proto fields.
3. `rotateLoginTOTPInTx`: return an explicit `InvalidArgument` error when `len(newEncrypted) > 0 != len(newNonce) > 0` (if `nonce` is not yet dropped from the API).
4. Better — replace with a single `envelope []byte` parameter: empty == drop, non-empty == upsert.

**Severity:** Medium (silent loss of 2FA after a routine operation).

---

## 2. Architectural suggestions

### 2.1. SQLite + Litestream instead of Postgres — a serious candidate

**Problem with the current architecture.** A self-hosted single-user manager hauls in:

- `pgxpool`, golang-migrate via iofs, RLS with custom GUC, `FOR UPDATE` for the audit chain, `LISTEN/NOTIFY` for SSE.
- Postgres configuration (`verify-full`, TLS certificates, pgaudit, backup via wal-g / pgBackRest).
- In docker-compose: the operator must bring up another container for PG, manage the volume, DB secrets, migrations.

All this while 99% of users are one person per instance, and **everything valuable is encrypted on the client anyway**. SQL is effectively used as a KV store with indexes.

**Alternative.** SQLite + WAL + Litestream (continuous replication to an S3-compatible bucket with Object Lock).

| What we gain                                                | What we lose                                                                                       |
| ----------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| One binary + one file — `oblivio start` works on a bare VPS | `LISTEN/NOTIFY` — replaced with in-process pub/sub (single process)                                |
| Backup = `cp` the file (or Litestream point-in-time)        | Multi-instance HA — needs SQLite primary/replica or a deliberate no                                |
| No network attack surface on the DB                         | Concurrent writes serialise (single writer) — but that's already our bottleneck in the audit chain |
| Restore = drop the file in place and start                  | RLS — replaced by trivial `WHERE user_id = ?` (already everywhere anyway)                          |
| Tests are an order of magnitude faster                      | Concurrent writes don't scale — but for self-hosted, that's not the goal                           |

Migration cost: pgx → `mattn/go-sqlite3` or `modernc.org/sqlite`, rewrite ~15 migrations (the SQL dialect is largely the same), drop River (see 2.3), drop LISTEN/NOTIFY (see 2.4), drop RLS helpers. About 3–5 person-days.

**Recommendation:** don't do this right now, but ask the question deliberately: "if we have one vault per user and the data is encrypted — why do we need Postgres?". If there's no answer beyond "habit / experience" — consider it.

---

### 2.2. Audit chain with external anchor — overkill; either simplify or redesign

**Problem.** The Ed25519 anchor lives on the same machine as the server ([internal/audit/anchor.go:60-115](../internal/audit/anchor.go#L60-L115)). The private key is in `data/secrets/audit_signer.json` under mode 0600. An attacker with RCE on the host gets:

- DB access (through the same process).
- The private key.
- → can re-sign any chain.

So the anchor only defends against an attacker with **DB-only** access (e.g. a DB dump leak). And if the DB lives on the same machine as the application, such attackers are rare.

§17.4 says this is "the target model — local signer for single-node, Vault transit for multi-node". But Vault transit is not yet wired up.

On top of that, in the current implementation the anchor does not work correctly (see 1.2). Fixing it also requires designing a proper high-water-mark scheme.

**Alternative A: simplify.** Remove the external anchor entirely. The hash chain in `audit_log + system_state.audit_chain_head` catches `1) accidental corruption` and `2) partial edits to the audit table via SQL without updating the head`. That is already a useful property. If OS-level security is sufficient (no shared DB access), the anchor adds nothing.

**Alternative B: redesign onto Vault transit.** Signatures performed by Vault, the private key never leaves Vault. That gives real DB-only protection. ~2 days of work.

**Alternative C: transparency log.** Publish `(head, height)` to an external WORM store hourly (e.g. `s3://oblivio-anchors/2026-05-12T14:00:00.json`) with Object Lock. That gives an undeniable external witness — a DB-resident attacker cannot retroactively sign a past head.

**Recommendation.** For single-user self-hosted: remove. For multi-tenant SaaS: Vault transit. A hybrid local-signer-on-disk scheme is the worst of both worlds.

**Additionally — overcomplicated threat model.** In a single-user password manager, only the user reads their audit log and only the user produces mutations. An attacker writing into the user's `audit_log` is an attacker who already owns the account. The `prev_hash → self_hash` protection is needed for compliance/forensics, not for blocking attacks. The intended constraint is "the sysadmin cannot silently erase their own actions" — but in self-hosted, sysadmin == user == DBA. The chain is a feature, not a security boundary. Trim it back and don't sell it as a security boundary.

---

### 2.3. River jobs — overkill for 8 periodic tasks

**Problem.** [internal/jobs/service.go:42-132](../internal/jobs/service.go#L42-L132) starts a River client with 8 workers:

- `audit_chain_verify` (1/day)
- `audit_chain_anchor` (1/hour)
- `sessions_gc`, `auth_tokens_gc`, `idempotency_gc`, `mfa_gc`, `recovery_gc`, `rate_limit_gc`

All are TTL cleanups and periodic alarms. None are retry-sensitive (if `sessions_gc` fails, the next run an hour later sweeps everything up).

River brings:

- ~10 tables in the DB for its own state (`river_job`, `river_leader`, etc.).
- Lock-based leader election.
- Backoff policies, retry logic.

For 8 cron-like tasks with no business outcome this is extreme overkill. If even one user-triggered job existed (email sending, password import, etc.) it would be justified. Here — no.

**Alternative.** `internal/jobs/service.go`, about 50 lines:

```go
go func() {
    t := time.NewTicker(cfg.AuditChainVerifyInterval)
    defer t.Stop()
    for { select { case <-ctx.Done(): return; case <-t.C: runVerify(ctx) } }
}()
// ... seven more times
```

Or `xutils/scheduler` / `robfig/cron` if you want crontab notation.

**Cost:** −3 migrations (River schema), −50 lines of wiring, minus the transitive dependency on `river/riverdriver/riverpgxv5`.

**What we lose:** persistent retry (but these jobs are already idempotent), distributed leader election (the single-node deploy doesn't use it).

**Severity:** Low (it works, just heavier than necessary). Makes sense at the next refactor.

---

### 2.4. SSE via LISTEN/NOTIFY — a real risk; entirely replaceable

**Problem.** [internal/api/subscriptions/service.go:51-104](../internal/api/subscriptions/service.go#L51-L104) — every active SSE stream holds **a separate PG connection** (LISTEN bound to that session). A pool of K connections caps you at K concurrent subscribers. On a reconnect storm (deploy, network blip) clients all retry → the pool drains → new logins start blocking.

Additional risks:

- A `pg_notify` payload is capped at **8000 bytes** (asymptotically). If you ever add a detailed payload, you'll hit the limit.
- If the channel is overflowing (`max_locks_per_transaction` or backlog), messages **are silently dropped**.
- One LISTEN connection per stream = `conn.Acquire(ctx)` blocking without a timeout → DoS vector: open 100 streams, drain the pool, and all API requests stall.

A 25-second heartbeat (`heartbeatInterval`) is good, but `WaitForNotification` with `context.WithTimeout` creates **a new timer per loop iteration** — not particularly cheap at thousands of connections.

**Alternative A: long-polling.** The client sends `Poll` every 10–30 seconds. The server responds immediately if something has changed (a cached counter in Redis or in-process), or waits until timeout. **No** LISTEN/NOTIFY, no extra connection pool, no heartbeat.

For a single-user password manager this is fine — there is no real-time criticality, and changes are rare (one per Create / Update).

**Alternative B: in-process pub/sub.** If we move to a single process (SQLite, see 2.1), publish directly into an in-memory bus → SSE stream. No DB connections, nothing.

**Alternative C: keep SSE but go through an in-process broker.** Every mutation handler does `broker.Publish(userID, kind)`. Every `Subscribe` listens on `broker.Subscribe(userID)`. Cross-instance is a separate problem (see multi-instance below).

**Recommendation.** Self-hosted: long-poll or in-process. Multi-instance: keep LISTEN/NOTIFY, but **monitor** connection leaks via a `subscriptions_active_connections` Prometheus metric and bound them.

---

### 2.5. Postgres-backed `ConsumeRateLimit` — correct, but painful

**Where:** [sql/queries/rate_limit_buckets/rate_limit_buckets.sql:11-27](../sql/queries/rate_limit_buckets/rate_limit_buckets.sql#L11-L27)

Every anonymous request does `INSERT ... ON CONFLICT DO UPDATE`. That means:

- A full transaction with a WAL write.
- A row-level lock on the bucket.
- A round-trip to the DB.

At 100 req/s on `GetKDFParams` that's 100 WAL writes per second just for rate limiting. On any non-minimal Postgres instance that's load, plus it generates bloat.

Fail-open on a DB error ([internal/api/middleware/rate_limit.go:105-110](../internal/api/middleware/rate_limit.go#L105-L110)) **amplifies the attack**: an attacker who also loads up the DB with parallel traffic disables rate limiting (queries become slow, the 500 ms timeout fires, fail-open returns true → Argon2 amplification).

**Alternative A: revert to in-memory, honestly single-node only.** For self-hosted that's the norm; multi-instance explicitly requires sticky sessions. ~30 lines of `golang.org/x/time/rate.Limiter`.

**Alternative B: Redis with TTL keys + Lua.** A standard pattern, no WAL needed.

**Alternative C: keep Postgres, but use an unlogged table and fail-closed.** `CREATE UNLOGGED TABLE rate_limit_buckets ...` — no WAL writes; DB restarts lose state (acceptable for rate limiting). Fail-closed: if the DB doesn't respond within 500 ms — return 503, don't let it through. That eliminates the amplification vector at the cost of brief user impact during a DB outage.

**Recommendation.** For current load (self-hosted) — C (unlogged). For scale — Redis.

---

### 2.6. ConnectRPC — only valuable for the one streaming endpoint; REST + EventSource is simpler

**Current state.** ConnectRPC + buf-generated stubs for Go and TS. Of all services, streaming is only used in `SubscriptionsService.Subscribe`. Everything else is unary.

ConnectRPC gives us:

- An auto-generated TS client.
- Proto-versioning (but `oblivio/v1` is the only version, and a migration is not on the roadmap).
- A binary wire format for backup efficiency (but most of the traffic is `encrypted_blob`, which is already raw bytes).

The alternative — REST + JSON + OpenAPI spec. Every endpoint explicit, easier to debug, no proto toolchain in CI.

**I don't recommend switching** (cost > benefit; ConnectRPC works). But it's an honest tradeoff in the "if I started from scratch" sense. For a separate browser extension or mobile client, proto stubs are genuinely useful; in 1–2 years that pays back the investment.

---

### 2.7. MFAKEK — three sources, two of them wrong; collapse to one mandatory

**Where:** [internal/auth/mfa_kek.go:42-79](../internal/auth/mfa_kek.go#L42-L79)

Three sources:

1. Seed from the argument (presumably from Vault).
2. `OBLIVIO_MFA_KEK_SEED` environment variable (resolved by the caller).
3. Per-instance random fallback.

(3) makes multi-instance deployment **silently broken** for cross-instance MFA challenges: a challenge created on instance A is not decryptable on instance B (different KEKs). `IsInstanceLocal()` is exposed, but operators may forget to check it and discover the pain in production.

A parallel case in the audit anchor: `LocalSigner` on disk vs. a hypothetical `VaultTransitSigner` — but the latter is not implemented.

**Alternative.** At server startup, if `OBLIVIO_MFA_KEK_SEED` (or a Vault path) is not set — **refuse to start** with an explicit error. Don't try to be "helpful" via a random fallback. Document: "for dev mode, set any seed; for prod, use a real sealed seed".

The same approach for `OBLIVIO_MASTER_SEED` (JWT signing) — there [internal/auth/secrets.go:97-145](../internal/auth/secrets.go#L97-L145) also falls back to on-disk `secrets.json` with a big WARN. That is less dangerous (single-node deploys usually work), but still surprise-shaped.

**Cost:** −30 lines, +1 line in `start.go` (a docs link in the error).

---

### 2.8. Vault integration — value still unrealised

From the docs: "HashiCorp Vault (optional) for server-side secrets". The code has no real Vault integration (I saw a mention of `xconfigvault` in the config layer). All three "protected" seeds (jwt-access, jwt-refresh, MFA KEK) are perfectly usable from `OBLIVIO_MASTER_SEED` / `OBLIVIO_MFA_KEK_SEED` env vars via HKDF. That's the best of both worlds: env-var-friendly (12-factor), and Vault Agent / sealed-secrets can populate them as needed.

**Recommendation.** Drop Vault from the roadmap as mandatory (or even as a supported mode). Document "12-factor secrets" as the canon. If someone uses Vault — let them inject through a Vault Agent sidecar into env vars.

---

## 3. Overcomplicated

### 3.1. `internal/audit/chain.go` canonical JSON

[internal/audit/chain.go:208-267](../internal/audit/chain.go#L208-L267) — 60 lines of hand-rolled sorted-JSON encoding (`marshalSorted`, `encodeSorted`, an insertion-sort `sortStrings`) for SHA-256 determinism over `audit_log.metadata`.

Go's `encoding/json` already **guarantees** key sorting for `map[string]X` since 1.12. It only guarantees the top level — but `metadata` in audit is user-supplied JSON of arbitrary depth, so a manual walk is required.

Alternative: use [`github.com/gibson042/canonicaljson-go`](https://github.com/gibson042/canonicaljson-go) (RFC 8785), or just `json.Marshal(any)` after `json.Unmarshal → map[string]any` recursively (which is what is happening, awkwardly).

Cost: ~5 lines, minus 60 lines of custom code. Bonus: RFC 8785 conformance lets a third-party tool trivially verify the chain.

### 3.2. `internal/audit/chain.go` insertion-sort

`sortStrings` ([line 271-277](../internal/audit/chain.go#L271-L277)) is a custom string insertion-sort. The standard library has `slices.Sort`. −7 lines.

### 3.3. `pseudoSaltSecret` / `pseudoBlindPepper` / `dummyAuthHash` — three separate anti-enumeration mechanisms

[internal/api/auth/service.go:1101-1166](../internal/api/auth/service.go#L1101-L1166) maintains three separate fallbacks:

- `pseudoSalt(email)` — HMAC of a process secret, for `GetKDFParams`.
- `pseudoBlindPepper(email)` — HMAC with a prefix, for the same.
- `dummyAuthHash()` — a fixed Argon2id PHC, for `Authorize`.

Unify: one helper `pseudoCredentials(email) → (salt, blind_pepper, argon_params)` plus one `dummyVerifyTime()` for timing. Semantics preserved, ~30 lines saved.

### 3.4. `audit_chain_anchor` + `audit_chain_verify` + Ed25519 `LocalSigner`

Together about 250 lines ([internal/audit/anchor.go](../internal/audit/anchor.go) + [internal/jobs/audit_chain_anchor.go](../internal/jobs/audit_chain_anchor.go) + anchor handling in verify) for functionality that, in the current implementation, protects nothing (see 1.2). If we decide not to fix it, those 250 lines go away entirely along with migration 010, the `repo_audit_chain_anchors` repository, and the `Signer` interface.

### 3.5. Parallel KEK sources for different purposes

`MFAKEK` ([internal/auth/mfa_kek.go](../internal/auth/mfa_kek.go)) — a dedicated KEK for exactly one use case: encrypting `auth_key` in `mfa_challenges`. The audit anchor uses its own Ed25519 key. JWT signing has its own pair. Email-verification tokens use SHA-256 without a key.

These can be unified: one process-wide `KEK` derived from `OBLIVIO_MASTER_SEED` via HKDF with different info labels. Then:

- `K_mfa_at_rest = HKDF(seed, "oblivio/mfa-kek/v1")` — same as today.
- `K_audit_signer = HKDF(seed, "oblivio/audit-signer/v1")` → a deterministic seed for Ed25519. No need for `audit_signer.json` on disk.
- `JWT_access = HKDF(seed, "oblivio/jwt-access/v1")` — already this way.

We remove a separate `audit_signer.json` file, a separate `NewMFAKEK` function, and a separate per-instance random fallback.

Cost: ~3 hours of work. The benefit is a simpler mental model: one seed, everything else deterministic.

---

## 4. Quick wins (an hour or two each)

**4.1.** [internal/auth/argon2.go:32](../internal/auth/argon2.go#L32) — `argon2Sem` is initialised globally at package init via `runtime.NumCPU()`. That happens BEFORE config is loaded; config then overwrites it via `SetArgon2Concurrency`. Between init and Set, a Hash/Verify call could race (if anything runs that early). Better: an explicit constructor and an instance on Manager, no global.

**4.2.** [internal/auth/argon2.go:59-71](../internal/auth/argon2.go#L59-L71) — `acquireArgon2` uses `context.Background()`. If a request is cancelled by the client while waiting in the queue, we still wait for a slot, burn CPU, compute Argon2, and throw it away. Accept `ctx` as a parameter and pass it through to `Acquire`.

**4.3.** [internal/audit/chain.go:79-83](../internal/audit/chain.go#L79-L83) — `Append` uses `IsoLevel: pgx.ReadCommitted` + `FOR UPDATE`. RR / Serializable are not needed, ReadCommitted is fine. But `defer tx.Rollback` after Commit always calls Rollback on an already committed transaction and returns an error (pgx logs it). The standard pattern is a `committed bool` flag (see [internal/api/middleware/rls.go:52-57](../internal/api/middleware/rls.go#L52-L57)).

**4.4.** [internal/api/subscriptions/service.go:67](../internal/api/subscriptions/service.go#L67) — `conn.Exec(ctx, fmt.Sprintf("LISTEN %s", quoteIdent(channel)))`. `quoteIdent` is fine, but `fmt.Sprintf` with a user-derived string in SQL is still a code smell. If `ChannelName` ever takes anything other than a UUID, security regresses easily. Add an assert or whitelist the character set.

**4.5.** [internal/api/middleware/idempotency.go:117](../internal/api/middleware/idempotency.go#L117) — `InsertIdempotencyEntry` without `ON CONFLICT DO NOTHING`. A concurrent race on the same key causes a PK violation and the operation runs twice (see also section 5). Change to `INSERT ... ON CONFLICT (user_id, key) DO NOTHING`.

**4.6.** [internal/audit/anchor.go:96-110](../internal/audit/anchor.go#L96-L110) — `NewLocalSigner` creates the file with 0600 permissions, but does not check that an existing file is private enough. If someone accidentally `chmod 0644`'d it, we trust a world-readable file. Add an `os.Stat` + a `Mode().Perm() == 0o600` check.

**4.7.** [internal/auth/secrets.go:32-41](../internal/auth/secrets.go#L32-L41) — `AccessSecret()` returns `string(s.access.Bytes())` — `string()` copies into immutable heap memory that cannot be zeroed. That contradicts the memguard promise. Better — pass `[]byte` through; tokenmanager should accept `[]byte`.

**4.8.** [internal/audit/chain.go:130-138](../internal/audit/chain.go#L130-L138) — `audit_chain_head` is stored as a JSON-encoded hex string inside JSONB. An extra encoding layer: JSONB wrapping `"deadbeef..."` instead of just BYTEA. Extra `json.Marshal` / `Unmarshal` per append. Change the column type to BYTEA, or at worst TEXT, and remove the round-trip.

**4.9.** [sql/queries/audit_chain_anchors/audit_chain_anchors.sql:6-9](../sql/queries/audit_chain_anchors/audit_chain_anchors.sql#L6-L9) — `GetLatestAuditChainAnchor` orders by `signed_at DESC`. With two signatures at the same instant (clock microsecond), the ordering is undefined. Better: `ORDER BY signed_at DESC, id DESC LIMIT 1` (id is BIGSERIAL).

**4.10.** [internal/api/auth/service.go:1106-1114](../internal/api/auth/service.go#L1106-L1114) — `pseudoSaltSecret` falls back to all-zeros on a `rand.Read` error. Should never happen, but if it did, every unknown email returns **the same** salt = `HMAC(zeros, email)`, which is in principle predictable (the attacker only needs to know the secret = zeros). Better `panic(err)` than silent zero.

**4.11.** [internal/api/auth/service.go:329](../internal/api/auth/service.go#L329) — after a successful `auth_key` verify, `CompleteMFA` checks the TOTP via `s.mfa.Peek` (not `Take`). If the TOTP fails, the challenge is not consumed and can be brute-forced. There is no per-IP rate limit on `CompleteMFA` ([rate_limit.go:170-196](../internal/api/middleware/rate_limit.go#L170-L196) — not in the list). 6 digits = 10^6 = a million; at ~3000 req/s you brute-force in 5 minutes (exactly the TTL). Add `CompleteMFA` to the rate-limit map and consume the challenge after N failed attempts.

**4.12.** Two metrics: `failed_attempts` (per-account lockout) and `RateLimitDropsTotal` (per-IP / email) give us **two** mechanisms. They can disagree (rate-limit let through, account-lockout blocked) and both require separate tuning. Unify behind an `auth_login_attempts(email, ip, at)` log with a sliding window; lockout becomes a policy result, not a side counter.

**4.13.** [internal/api/middleware/rate_limit.go:54](../internal/api/middleware/rate_limit.go#L54) — `proceduresWithRateLimit` does not include `/oblivio.v1.AuthService/CompleteMFA`. Add it.

---

## 5. What not to touch

**5.1. AAD binding on entries / projects ([frontend/src/lib/vault-crypto.ts:112-148](../frontend/src/lib/vault-crypto.ts#L112-L148)).** The structure `${itemId}|${version}|${vaultId}|item` correctly defends against swap attacks even from an honest server: substituting user A's entry for user B's is impossible (different `vault_id = user_id`, AAD won't validate). The verifier fails AES-GCM tag on substitution.

**5.2. RLS policies and FORCE ROW LEVEL SECURITY ([sql/migrations/005_rls_policies.up.sql](../sql/migrations/005_rls_policies.up.sql)).** Using two GUCs (`app.current_user_id` per user, `app.bypass_rls` for the system), `app_is_system()`, and `app_current_user_id()` via `current_setting(..., true)` — sound. FORCE RLS is correctly applied. `audit_log` read-only for the user, insert only for the system — correct.

**5.3. Envelope format `version(1) || nonce(12) || ct+tag` ([internal/crypto/aead.go](../internal/crypto/aead.go), [frontend/packages/crypto/src/aead.ts](../frontend/packages/crypto/src/aead.ts)).** Go and TS implementations are identical, the version byte provides an upgrade path. The AAD on v1 does not cover the version byte, but decode rejects unknown versions before the AEAD operation — that's enough.

**5.4. Refresh-token reuse detection ([internal/auth/manager.go:188-209](../internal/auth/manager.go#L188-L209)).** The approach of stamping `current_refresh_key` and using `bytes.Equal` to detect reuse is correct. There is a race (see a mini-finding in section 4), but the basic idea is sound.

**5.5. `tokenmanager` + PG-backed store.** Separating access / refresh keys with different TTLs and storing per-session `SessionData` in PG — solid. The Sessions UI works.

**5.6. Argon2 semaphore ([internal/auth/argon2.go:30-71](../internal/auth/argon2.go#L30-L71)).** Logic is correct (acquire/release around IDKey). Comments explain why `context.Background` is OK. `SetArgon2Concurrency` is safe for startup-only wiring.

**5.7. `MFAStore.Take` = atomic `DELETE RETURNING` ([internal/auth/mfa_store.go:130-152](../internal/auth/mfa_store.go#L130-L152)).** The SQL layer guarantees that only one caller wins the row. Peek + Take in the WebAuthn flow is the correct pattern for the race between assertion validation and cleanup.

**5.8. memguard in `DeriveLoginTOTPKey` ([internal/auth/login_totp.go:44-56](../internal/auth/login_totp.go#L44-L56)).** `NewBufferFromBytes` wipes the source; `defer Destroy` on the buffer — correct. Replacing `string(secret)` with the byte-slice variant (`ValidateTOTPCodeBytes`) is a real improvement.

**5.9. Anti-enumeration via `pseudoSalt` for `GetKDFParams` ([internal/api/auth/service.go:236-242](../internal/api/auth/service.go#L236-L242)).** The concept is correct (stable pseudo-parameters for unknown emails). The implementation has two issues (see 1.4 and 4.10), but does not need a from-scratch rewrite.

**5.10. ConnectRPC interceptor chain.** Anonymous allow-list + Bearer-token middleware + RLS interceptor + audit-log interceptor + idempotency middleware — the layer ordering is correct.

**5.11. memguard coverage on server-side keys ([internal/auth/secrets.go](../internal/auth/secrets.go)).** Using `NewBufferFromBytes` for the access / refresh seeds is correct. The one issue with the `string()` copy (4.7) is a small thing.

---

## 6. What I would do differently from scratch

One day, same brief — a zero-knowledge password manager whose baseline scenario is single-user self-hosted, with mobile / extension in the future.

**Stack.**

- **Storage:** SQLite + WAL + Litestream → S3 with Object Lock. One file, trivial backup, no network attack surface on the DB.
- **Transport:** REST + JSON + OpenAPI spec. The OpenAPI generates the TS client. Streaming is a single SSE endpoint `/events` with long-poll fallback.
- **Server framework:** Go + chi/echo + the standard library `database/sql`. No mx-launcher (overkill for one binary).
- **Crypto model:** identical to the current one. Argon2id master_key, HKDF auth_key, vault_key / item_key / blind_index — that layer is excellent as-is.
- **2FA:** WebAuthn only in the MVP. Login-TOTP adds enormous complexity (server-side secret derived from `auth_key`, ChangeMasterPassword rotation, recovery rotation) for the sake of compatibility with Google Authenticator. The modern flow is passkeys, and the user starts by registering a passkey; TOTP is added optionally as a low-tech backup. **MVP — skip; add in sprint two.**

**What we throw out.**

- **Postgres.** SQLite single-writer is enough for a single user.
- **RLS.** A single user-bound query is `WHERE user_id = ?`. No GUC + interceptor + bypass needed.
- **River jobs.** A goroutine + ticker × 4 (verify, sessions GC, idempotency GC, mfa GC). Enough.
- **Audit external anchor.** In single-user self-hosted there is no threat model where it really helps. The DB hash chain stays.
- **MFAKEK.** MFA challenge lives in an in-memory store (as it did before the PG migration). 5-minute TTL, no sticky session needed (single process).
- **Postgres LISTEN/NOTIFY.** In-process pub/sub broker. SSE is plugged in directly.
- **Postgres-based rate limiting.** `golang.org/x/time/rate` per IP + per email, in-memory. Single-node only is documented.
- **Vault.** Env vars only. `OBLIVIO_SEED` (32+ bytes hex/base64) is mandatory at startup; everything else (JWT, MFAKEK if we keep it, anchor) is derived via HKDF.
- **ConnectRPC.** REST + OpenAPI codegen.
- **memguard on the server.** It genuinely protects only the JWT seed and `K_login_totp` (if TOTP stays). For everything else — plain Go GC. Honestly document "memguard for the JWT seed only".

**What we add.**

- **Recovery code rotation on `RecoveryComplete` + `ChangeMasterPassword`** (see 1.1).
- **Audit chain without external anchor** — but with **append-only** at the filesystem level: the SQLite audit_log table on an extra WORM FS (`overlayfs` on top of a read-only nfs / s3 mount, or just `chattr +a` on an ext4 file). That gives an honest "you can't delete a row without alerting".
- **External witness via append-to-file:** duplicate every Nth row into a plain-text log `audit.log` in a WORM folder. At the perimeter — Litestream backup with object-lock.

**Proto-like structure (but JSON).**

```text
POST /v1/auth/register       (anonymous, rate-limited)
POST /v1/auth/kdf-params     (anonymous, rate-limited)
POST /v1/auth/authorize      (anonymous, rate-limited)
POST /v1/auth/refresh
POST /v1/auth/logout
POST /v1/auth/change-password
GET  /v1/me                  (auth)
GET  /v1/projects            (auth)
... entries, audit, sessions
GET  /v1/events              (auth, SSE, long-poll)
```

**Development velocity.** Less pipeline (buf + protoc + Connect TS stubs + Vite), faster change cycle. One binary — deploy via `scp + systemd`, operator-friendly.

**What we lose.** Multi-instance, multi-tenant SaaS — won't scale without a refactor. That's a deliberate choice: "self-hosted manager for one person / one family" ≠ "cloud SaaS like Bitwarden".

**MVP size.** ~10k lines of Go + ~5k lines of TS, versus the current ~30k + 10k. A 2–3× reduction in attack surface and support surface.

---

## Summary

The current implementation is a solid zero-knowledge architecture with the right split — "crypto on the client, ciphertext + metadata on the server". Cryptographic primitives are correct, AEAD envelopes are aligned Go↔TS, HKDF info labels are versioned, RLS is wired properly.

The main defects are **not in the crypto, but in the policies around it**:

1. Recovery code as a permanent backdoor (§1.1).
2. The audit anchor that doesn't run on a "clean" chain (§1.2).
3. DoS vector via permanent account lockout (§1.3).
4. Timing side channels in anti-enumeration (§1.4).
5. Silent TOTP drop on partial input during rotation (§1.5).

And the "honest architectural overhead" — the combination of Postgres + River + LISTEN/NOTIFY + Vault + memguard + ConnectRPC gives good protection, but **for the current goal** (self-hosted single-user manager) it is overkill in precisely the parts that are beautifully engineered.

§17 "known limitations" is honest, but **should be expanded** with items §1.1, §1.2, §1.3, §1.4 — those are not reified compromises, they are found bugs.

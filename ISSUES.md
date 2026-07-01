# Known Issues

Non-vulnerability observations from the security review of the hardening
rollup (`73e0b42`). None of these are exploitable today; they are tracked
here so the intent behind each control stays honest.

## 1. `audit_log` deny policies are PERMISSIVE, so they don't guarantee what their comment claims

- **Where:** `sql/migrations/013_security_hardening.up.sql:35-42`
  (`audit_log_immutable_no_update`, `audit_log_immutable_no_delete`)
- **Type:** hardening gap (no current exploit)

The F-10 policies are created without `AS RESTRICTIVE`, so they are
PERMISSIVE. Postgres combines permissive policies with OR: a `USING (false)`
permissive policy grants nothing, but it also *blocks* nothing. Today
`audit_log` has no UPDATE/DELETE policy at all, so those commands are
already denied by default — behavior is unchanged. But the migration
comment says these policies exist "so a future `FOR ALL` policy cannot
accidentally widen the surface", and that guarantee does not hold: a future
permissive `FOR ALL ... USING (true)` policy would OR past them and allow
UPDATE/DELETE anyway.

**Fix:** recreate both policies with `AS RESTRICTIVE` (restrictive policies
AND with the permissive set), which makes the comment's guarantee real.
Needs a follow-up migration.

## 2. `ChangeMasterPassword` verifies the old auth key without checking `locked_until`

- **Where:** `internal/api/auth/service.go:715` (function),
  `internal/api/auth/service.go:734-739` (wrong-old-key path)
- **Type:** pre-existing hardening debt (inherited from the parent commit,
  not introduced by `73e0b42`)

`Authorize` (service.go:297) and `RecoveryStart` (service.go:931) refuse
locked accounts before running Argon2 verification. `ChangeMasterPassword`
does not: it loads `user_auth`, runs `auth.VerifyAuthKey` on the presented
old key, and on failure increments the lockout counter via
`RecordFailedLogin` — but it never checks `ua.LockedUntil` first. A caller
holding a valid Bearer session can therefore keep submitting old-key
guesses through an active lock window; each guess still costs a full
server-side Argon2 verify and returns a distinguishable result.

Impact is limited because the endpoint requires an authenticated session
(the attacker already holds a token but wants the master-password-derived
key, e.g. a stolen device with an unlocked tab). Still, the lockout should
apply uniformly to every auth-key verifier.

**Fix:** mirror the `Authorize` guard — return `ResourceExhausted` (or the
uniform unauthenticated error) when `ua.LockedUntil` is in the future,
before calling `VerifyAuthKey`.

## 3. M-6 (source-IP / bind-token binding for recovery sessions and MFA challenges) is deferred

- **Where:** documented in the header of
  `sql/migrations/013_security_hardening.up.sql:15-20`
- **Type:** deferred control (tracking item)

The hardening rollup deliberately does not ship IP or bind-token binding
for `recovery_sessions` / `mfa_challenges`: it requires plumbing the
request IP into the handlers (absent today) and a wire-protocol field the
client round-trips. An intermediate revision added the columns unwired and
they were correctly removed before commit — shipping columns the code
never enforces would advertise a control that doesn't exist.

Until M-6 lands, a recovery session or MFA challenge id intercepted
mid-flow can be completed from a different network vantage point than the
one that started it. Compensating controls exist (short TTLs, per-email and
per-IP rate limits, challenge burn after 5 failed MFA attempts, single-use
`Take` semantics).

**Fix:** dedicated change that adds the columns together with request-IP
plumbing and client round-trip of a bind token, then enforces both on
`CompleteMFA` / `RecoveryComplete`.

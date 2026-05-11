-- Shared, multi-instance state for the auth subsystem.
-- Plan §17.3: rate-limit, MFA challenges, and recovery sessions were
-- in-memory per-process. Moving them to Postgres lets two instances behind a
-- load balancer agree on a single token-bucket and a single MFA-completion
-- handshake without sticky sessions.

-- Token-bucket counters. Each bucket is identified by (kind, key), e.g.
-- kind="auth_login_ip", key="203.0.113.7". `tokens` is updated atomically
-- via an arithmetic refill on every Allow() call (see middleware/rate_limit.go).
CREATE TABLE rate_limit_buckets (
    kind         TEXT NOT NULL,
    key          TEXT NOT NULL,
    tokens       DOUBLE PRECISION NOT NULL,
    refilled_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, key)
);
CREATE INDEX idx_rate_limit_refilled ON rate_limit_buckets(refilled_at);

-- MFA challenges issued after a successful auth_key check. The auth_key
-- bytes are stored as AES-GCM ciphertext under a process/cluster-local KEK
-- (internal/auth/mfa_kek.go) so a DB dump alone is insufficient to recover
-- the secret-equivalent material. webauthn_state is JSON-serialised
-- go-webauthn SessionData.
CREATE TABLE mfa_challenges (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email          TEXT NOT NULL,
    auth_key_ct    BYTEA NOT NULL,    -- AES-GCM(KEK, auth_key); env: nonce||ct||tag
    device_id      TEXT NOT NULL,
    device_type    TEXT NOT NULL,
    device_name    TEXT NOT NULL,
    totp_required  BOOLEAN NOT NULL,
    webauthn_state JSONB,
    expires_at     TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_mfa_challenges_expires ON mfa_challenges(expires_at);

-- Recovery sessions: a successfully-proven recovery_code grants a short-lived
-- handle the client must present at RecoveryComplete. No secret material is
-- stored here — the row alone is just a capability token.
CREATE TABLE recovery_sessions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email       TEXT NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_recovery_sessions_expires ON recovery_sessions(expires_at);

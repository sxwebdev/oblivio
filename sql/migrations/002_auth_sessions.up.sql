-- Per-device session metadata surfaced by SessionsService and used by the
-- auth Manager to coordinate revocation. The actual access/refresh token
-- state lives in auth_tokens (PG-backed tokenmanager.ITokenStore) below;
-- this table is the human-facing aggregate (device, ip, last seen).
--
-- access_token_hash / refresh_token_hash are nullable forensic columns —
-- they are not used for revocation (auth_tokens is the source of truth).
CREATE TABLE auth_sessions (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id              UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id            TEXT NOT NULL,
    device_type          TEXT NOT NULL,
    device_name          TEXT,
    ip                   INET,
    country              TEXT,
    access_token_hash    BYTEA,
    refresh_token_hash   BYTEA,
    -- current_refresh_key is the auth_tokens.key of the latest refresh
    -- token issued for this session. Refresh handler compares the
    -- presented refresh's derived key against this column; mismatch =
    -- token theft → full session sweep (plan §13.3).
    current_refresh_key  BYTEA,
    access_expires_at    TIMESTAMPTZ NOT NULL,
    refresh_expires_at   TIMESTAMPTZ NOT NULL,
    revoked_at           TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, device_id)
);

CREATE INDEX idx_sessions_refresh_hash ON auth_sessions(refresh_token_hash) WHERE revoked_at IS NULL;
CREATE INDEX idx_sessions_access_hash  ON auth_sessions(access_token_hash)  WHERE revoked_at IS NULL;

-- PG-backed store for tokenmanager.ITokenStore. Replaces the in-memory
-- MemoryTokenStore so that revocation (Logout, TerminateSession,
-- ChangeMasterPassword, RecoveryComplete) actually invalidates live
-- tokens and survives a process restart.
--
-- `key` mirrors the tokenmanager `getKey()` output (raw bytes including
-- the "tokenmanager:" prefix). The user_id / session_id / token_type
-- columns are denormalised from the JSON value at INSERT time so we can
-- do O(1) revocation by user or by session without a JSONB scan.
-- user_id has ON DELETE CASCADE so DeleteMe atomically wipes every token
-- belonging to the deleted account inside the same RLS-tx — no orphan
-- tokens, no race window between user delete and explicit revoke.
-- session_id is intentionally NOT FK'd: when auth_sessions is GC'd we
-- want auth_tokens reaped on its own schedule (expires_at index) so
-- terminated sessions stay visible in audit/UI for a few hours.
CREATE TABLE auth_tokens (
    key         BYTEA       PRIMARY KEY,
    value       BYTEA       NOT NULL,
    user_id     UUID        REFERENCES users(id) ON DELETE CASCADE,
    session_id  UUID,
    token_type  TEXT        NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_auth_tokens_user    ON auth_tokens(user_id)    WHERE user_id    IS NOT NULL;
CREATE INDEX idx_auth_tokens_session ON auth_tokens(session_id) WHERE session_id IS NOT NULL;
CREATE INDEX idx_auth_tokens_expiry  ON auth_tokens(expires_at);

CREATE TABLE auth_sessions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id           TEXT NOT NULL,
    device_type         TEXT NOT NULL,
    device_name         TEXT,
    ip                  INET,
    country             TEXT,
    access_token_hash   BYTEA NOT NULL,
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

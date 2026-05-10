-- WebAuthn / passkey credentials. One row per registered authenticator;
-- a user may have many. Public key + sign_count are checked at every
-- assertion to detect cloned authenticators.
CREATE TABLE user_webauthn_credentials (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    credential_id   BYTEA UNIQUE NOT NULL,
    public_key      BYTEA NOT NULL,
    aaguid          BYTEA,
    sign_count      BIGINT NOT NULL DEFAULT 0,
    transports      TEXT[] NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ
);
CREATE INDEX idx_webauthn_user_id ON user_webauthn_credentials(user_id);

-- RLS: a user only sees their own credentials.
ALTER TABLE user_webauthn_credentials ENABLE ROW LEVEL SECURITY;
CREATE POLICY webauthn_owner ON user_webauthn_credentials
    USING (user_id = app_current_user_id())
    WITH CHECK (user_id = app_current_user_id());

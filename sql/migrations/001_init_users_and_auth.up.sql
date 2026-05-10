CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

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
    verifier                      BYTEA NOT NULL,
    wrapped_vault_key             BYTEA NOT NULL,
    vault_key_version             INT   NOT NULL DEFAULT 1,
    recovery_salt                 BYTEA NOT NULL,
    recovery_wrapped_vault_key    BYTEA NOT NULL,
    recovery_proof_hash           TEXT  NOT NULL,
    recovery_used_at              TIMESTAMPTZ
);

CREATE TABLE user_login_totp (
    user_id             UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    -- AES-GCM(K_login_totp, totp_secret); K_login_totp = HKDF(auth_key, "login-totp/v1")
    encrypted_secret    BYTEA NOT NULL,
    nonce               BYTEA NOT NULL,
    enabled             BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- WebAuthn / passkey credentials. One row per registered authenticator;
-- a user may have many. Public key + sign_count are checked at every
-- assertion to detect cloned authenticators.
--
-- `flags` stores the raw authenticator-data flags byte. The go-webauthn
-- library enforces that the BackupEligible flag is identical between
-- registration and login (WebAuthn §7.2 "Backup Eligible flag is
-- immutable"). Without persisting it, any passkey that registered with
-- BE=1 (Apple iCloud Keychain, Chrome sync, …) would fail subsequent
-- assertions with "Backup Eligible flag inconsistency detected".
--
-- `unlock_wrapped_vault_key` + `prf_salt` are the per-credential
-- passkey-unlock bundle. When the user opts into "unlock with this
-- passkey" we store a second wrapped_vault_key sealed under a key
-- derived from the WebAuthn PRF extension output. The prf_salt is
-- echoed back to the client at unlock time so the browser passes the
-- same salt into prf.eval.first and gets the same PRF output
-- (otherwise the wrapping key differs and AES-GCM auth fails). Both
-- columns are NULL when unlock is not enabled for the credential; they
-- are written atomically (set_webauthn_unlock_bundle query) so a
-- half-populated row cannot exist.
CREATE TABLE user_webauthn_credentials (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name                     TEXT NOT NULL,
    credential_id            BYTEA UNIQUE NOT NULL,
    public_key               BYTEA NOT NULL,
    aaguid                   BYTEA,
    sign_count               BIGINT NOT NULL DEFAULT 0,
    transports               TEXT[] NOT NULL DEFAULT '{}',
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at             TIMESTAMPTZ,
    flags                    SMALLINT NOT NULL DEFAULT 0,
    unlock_wrapped_vault_key BYTEA NULL,
    prf_salt                 BYTEA NULL
);
CREATE INDEX idx_webauthn_user_id ON user_webauthn_credentials(user_id);

COMMENT ON COLUMN user_webauthn_credentials.unlock_wrapped_vault_key IS
    'AES-GCM(HKDF(prf_output), vault_key) with AAD=user_id||credential_id. NULL = unlock not enabled.';
COMMENT ON COLUMN user_webauthn_credentials.prf_salt IS
    'Per-credential 32-byte salt passed as prf.eval.first at WebAuthn get(). NULL iff unlock_wrapped_vault_key is NULL.';

-- RLS: a user only sees their own credentials. Trusted system paths
-- (auth-service during Authorize) bypass via app.bypass_rls.
ALTER TABLE user_webauthn_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_webauthn_credentials FORCE  ROW LEVEL SECURITY;
CREATE POLICY webauthn_owner ON user_webauthn_credentials
    USING       (app_is_system() OR user_id = app_current_user_id())
    WITH CHECK  (app_is_system() OR user_id = app_current_user_id());

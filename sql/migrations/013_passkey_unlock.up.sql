-- Per-credential passkey unlock material. When the user opts into
-- "unlock with this passkey" we store a second wrapped_vault_key sealed
-- under a key derived from the WebAuthn PRF extension output. The
-- accompanying prf_salt is echoed back to the client at unlock time so
-- the browser passes the same salt into prf.eval.first and gets the
-- same PRF output (otherwise the wrapping key differs and AES-GCM auth
-- fails). Both columns are NULL when unlock is not enabled for the
-- credential. They are populated atomically (see queries.set_webauthn_
-- unlock_bundle) so a partially-populated row cannot exist.
ALTER TABLE user_webauthn_credentials
    ADD COLUMN unlock_wrapped_vault_key BYTEA NULL,
    ADD COLUMN prf_salt                 BYTEA NULL;

COMMENT ON COLUMN user_webauthn_credentials.unlock_wrapped_vault_key IS
    'AES-GCM(HKDF(prf_output), vault_key) with AAD=user_id||credential_id. NULL = unlock not enabled.';
COMMENT ON COLUMN user_webauthn_credentials.prf_salt IS
    'Per-credential 32-byte salt passed as prf.eval.first at WebAuthn get(). NULL iff unlock_wrapped_vault_key is NULL.';

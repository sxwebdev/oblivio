ALTER TABLE user_webauthn_credentials
    DROP COLUMN IF EXISTS unlock_wrapped_vault_key,
    DROP COLUMN IF EXISTS prf_salt;

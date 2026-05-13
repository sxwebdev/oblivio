-- name: ListWebAuthnCredentials :many
SELECT * FROM user_webauthn_credentials
WHERE user_id = $1
ORDER BY created_at DESC;

-- name: CountWebAuthnCredentials :one
SELECT COUNT(*) FROM user_webauthn_credentials WHERE user_id = $1;

-- name: GetWebAuthnCredentialByID :one
SELECT * FROM user_webauthn_credentials
WHERE id = $1 AND user_id = $2;

-- name: GetWebAuthnCredentialByCredID :one
SELECT * FROM user_webauthn_credentials WHERE credential_id = $1;

-- name: CreateWebAuthnCredential :one
INSERT INTO user_webauthn_credentials (
    user_id, name, credential_id, public_key, aaguid, sign_count, transports, flags
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: TouchWebAuthnCredential :exec
UPDATE user_webauthn_credentials
SET sign_count   = $2,
    flags        = $3,
    last_used_at = now()
WHERE id = $1;

-- name: DeleteWebAuthnCredential :exec
DELETE FROM user_webauthn_credentials
WHERE id = $1 AND user_id = $2;

-- name: SetWebAuthnUnlockBundle :exec
UPDATE user_webauthn_credentials
SET unlock_wrapped_vault_key = $3,
    prf_salt                 = $4
WHERE id = $1 AND user_id = $2;

-- name: ClearWebAuthnUnlockBundle :exec
UPDATE user_webauthn_credentials
SET unlock_wrapped_vault_key = NULL,
    prf_salt                 = NULL
WHERE id = $1 AND user_id = $2;

-- name: ClearAllWebAuthnUnlockBundles :exec
UPDATE user_webauthn_credentials
SET unlock_wrapped_vault_key = NULL,
    prf_salt                 = NULL
WHERE user_id = $1
  AND (unlock_wrapped_vault_key IS NOT NULL OR prf_salt IS NOT NULL);

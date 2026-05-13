-- name: GetUserLoginTOTP :one
SELECT * FROM user_login_totp WHERE user_id = $1;

-- name: UpsertUserLoginTOTP :exec
INSERT INTO user_login_totp (user_id, encrypted_secret, nonce, enabled)
VALUES ($1, $2, $3, $4)
ON CONFLICT (user_id) DO UPDATE
SET encrypted_secret = EXCLUDED.encrypted_secret,
    nonce            = EXCLUDED.nonce,
    enabled          = EXCLUDED.enabled;

-- name: DeleteUserLoginTOTP :exec
DELETE FROM user_login_totp WHERE user_id = $1;

-- name: GetSessionByID :one
SELECT * FROM auth_sessions WHERE id = $1 AND revoked_at IS NULL;

-- name: GetSessionByAccessHash :one
SELECT * FROM auth_sessions
WHERE access_token_hash = $1 AND revoked_at IS NULL;

-- name: GetSessionByRefreshHash :one
SELECT * FROM auth_sessions
WHERE refresh_token_hash = $1 AND revoked_at IS NULL;

-- name: UpsertSession :one
INSERT INTO auth_sessions (
    user_id, device_id, device_type, device_name,
    ip, country,
    access_token_hash, refresh_token_hash,
    access_expires_at, refresh_expires_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (user_id, device_id) DO UPDATE
SET device_type        = EXCLUDED.device_type,
    device_name        = EXCLUDED.device_name,
    ip                 = EXCLUDED.ip,
    country            = EXCLUDED.country,
    access_token_hash  = EXCLUDED.access_token_hash,
    refresh_token_hash = EXCLUDED.refresh_token_hash,
    access_expires_at  = EXCLUDED.access_expires_at,
    refresh_expires_at = EXCLUDED.refresh_expires_at,
    revoked_at         = NULL,
    last_seen_at       = now()
RETURNING *;

-- name: RotateSession :exec
UPDATE auth_sessions
SET access_token_hash  = $2,
    refresh_token_hash = $3,
    access_expires_at  = $4,
    refresh_expires_at = $5,
    last_seen_at       = now()
WHERE id = $1;

-- name: RevokeSession :exec
UPDATE auth_sessions SET revoked_at = now() WHERE id = $1;

-- name: RevokeAllUserSessions :exec
UPDATE auth_sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL;

-- name: ListUserSessions :many
SELECT * FROM auth_sessions
WHERE user_id = $1 AND revoked_at IS NULL
ORDER BY last_seen_at DESC;

-- name: GetSessionByID :one
SELECT * FROM auth_sessions WHERE id = $1 AND revoked_at IS NULL;

-- The legacy GetSessionByAccessHash / GetSessionByRefreshHash queries were
-- removed: the auth_tokens table is now the source of truth for token
-- validity, and auth_sessions.{access,refresh}_token_hash are no longer
-- written.

-- name: TouchSession :exec
-- Drives the "recently active" UI sort.
UPDATE auth_sessions SET last_seen_at = now() WHERE id = $1;

-- name: SetSessionCurrentRefreshKey :exec
UPDATE auth_sessions
SET current_refresh_key = $2,
    last_seen_at        = now()
WHERE id = $1;

-- name: GetSessionCurrentRefreshKey :one
-- revoked_at IS NULL — a refresh against a revoked session must surface as
-- ErrRefreshReuse (no row), not silently swap a new token pair onto a
-- session that was supposed to be dead (M-7 / H-3).
SELECT current_refresh_key FROM auth_sessions WHERE id = $1 AND revoked_at IS NULL;

-- name: UpsertSession :one
-- access_token_hash / refresh_token_hash are nullable since the source of
-- truth for token validity moved to the auth_tokens table. We no longer
-- write them.
INSERT INTO auth_sessions (
    user_id, device_id, device_type, device_name,
    ip, country,
    access_expires_at, refresh_expires_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (user_id, device_id) DO UPDATE
SET device_type        = EXCLUDED.device_type,
    device_name        = EXCLUDED.device_name,
    ip                 = EXCLUDED.ip,
    country            = EXCLUDED.country,
    access_expires_at  = EXCLUDED.access_expires_at,
    refresh_expires_at = EXCLUDED.refresh_expires_at,
    revoked_at         = NULL,
    last_seen_at       = now()
RETURNING *;

-- name: RevokeSession :exec
UPDATE auth_sessions SET revoked_at = now() WHERE id = $1;

-- name: RevokeAllUserSessions :exec
UPDATE auth_sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL;

-- name: RevokeAllUserSessionsExcept :execrows
UPDATE auth_sessions SET revoked_at = now()
WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL;

-- name: ListUserSessions :many
SELECT * FROM auth_sessions
WHERE user_id = $1 AND revoked_at IS NULL
ORDER BY last_seen_at DESC;

-- name: DeleteExpiredSessions :execrows
-- Reaps rows whose refresh has expired or that have been revoked far enough
-- in the past that the audit chain already captured the termination event.
-- Keeping revoked rows around briefly lets "I just logged out from the other
-- tab" investigations succeed; 24h is long enough for that.
DELETE FROM auth_sessions
WHERE refresh_expires_at < $1
   OR (revoked_at IS NOT NULL AND revoked_at < $1);

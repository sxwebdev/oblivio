-- name: GetAuthToken :one
SELECT key, value, user_id, session_id, token_type, expires_at, created_at
FROM auth_tokens
WHERE key = $1 AND expires_at > now();

-- name: AuthTokenExists :one
SELECT EXISTS(
    SELECT 1 FROM auth_tokens WHERE key = $1 AND expires_at > now()
);

-- name: UpsertAuthToken :exec
INSERT INTO auth_tokens (key, value, user_id, session_id, token_type, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (key) DO UPDATE
SET value      = EXCLUDED.value,
    user_id    = EXCLUDED.user_id,
    session_id = EXCLUDED.session_id,
    token_type = EXCLUDED.token_type,
    expires_at = EXCLUDED.expires_at;

-- name: DeleteAuthToken :exec
DELETE FROM auth_tokens WHERE key = $1;

-- name: ListAuthTokensByPrefix :many
-- Used by tokenmanager.ITokenStore.Keys / KeysAndValues. Empty prefix → all rows.
SELECT key, value FROM auth_tokens
WHERE expires_at > now()
  AND (sqlc.arg(prefix)::bytea = ''::bytea OR key >= sqlc.arg(prefix)::bytea AND key < (sqlc.arg(prefix)::bytea || E'\\xFF'::bytea));

-- name: DeleteAuthTokensBySession :execrows
DELETE FROM auth_tokens WHERE session_id = $1;

-- name: DeleteAuthTokensByUser :execrows
DELETE FROM auth_tokens
WHERE user_id = $1
  AND (sqlc.narg(except_session_id)::uuid IS NULL OR session_id <> sqlc.narg(except_session_id));

-- name: DeleteExpiredAuthTokens :execrows
DELETE FROM auth_tokens WHERE expires_at <= now();

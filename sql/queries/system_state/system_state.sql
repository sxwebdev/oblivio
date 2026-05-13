-- name: GetSystemValue :one
SELECT value FROM system_state WHERE key = $1;

-- name: UpsertSystemValue :exec
INSERT INTO system_state (key, value, updated_at)
VALUES ($1, $2, now())
ON CONFLICT (key) DO UPDATE
SET value = EXCLUDED.value, updated_at = now();

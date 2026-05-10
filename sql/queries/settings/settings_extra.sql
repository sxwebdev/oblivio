-- name: UpsertSetting :one
INSERT INTO settings (key, value, updated_at)
VALUES ($1, $2, now())
ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = now()
RETURNING *;

-- name: GetAllSettings :many
SELECT * FROM settings ORDER BY key;

-- name: ListProjects :many
SELECT * FROM projects
WHERE user_id = $1
ORDER BY sort_order ASC, created_at ASC;

-- name: GetProject :one
SELECT * FROM projects
WHERE id = $1 AND user_id = $2;

-- name: CreateProject :one
INSERT INTO projects (
    user_id, encrypted_blob, wrapped_item_key, name_hash, sort_order
) VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: UpdateProject :one
UPDATE projects
SET encrypted_blob   = $3,
    wrapped_item_key = $4,
    name_hash        = $5,
    version          = version + 1,
    updated_at       = now()
WHERE id = $1 AND user_id = $2 AND version = sqlc.arg(expected_version)
RETURNING *;

-- name: DeleteProject :execrows
DELETE FROM projects
WHERE id = $1 AND user_id = $2 AND version = sqlc.arg(expected_version);

-- name: ReorderProject :exec
UPDATE projects SET sort_order = $3, updated_at = now()
WHERE id = $1 AND user_id = $2;

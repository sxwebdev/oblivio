-- name: ListEntries :many
-- Filters: project_id (NULLable; pass NULL to match all), kind, title_hashes,
-- domain_hashes, favorites_only, has_totp, updated_after. Pagination with
-- cursor (updated_at, id) ordering DESC by updated_at.
SELECT *
FROM entries
WHERE user_id = $1
  AND (sqlc.narg(project_id)::uuid     IS NULL OR project_id = sqlc.narg(project_id))
  AND (sqlc.narg(kind)::entry_kind     IS NULL OR kind = sqlc.narg(kind))
  AND (sqlc.narg(title_hashes)::bytea[] IS NULL OR title_hash = ANY(sqlc.narg(title_hashes)::bytea[]))
  AND (sqlc.narg(domain_hashes)::bytea[] IS NULL OR domain_hash = ANY(sqlc.narg(domain_hashes)::bytea[]))
  AND (sqlc.narg(favorites_only)::bool IS NULL OR is_favorite = sqlc.narg(favorites_only))
  AND (sqlc.narg(has_totp_only)::bool  IS NULL OR has_totp    = sqlc.narg(has_totp_only))
  AND (sqlc.narg(updated_after)::timestamptz IS NULL OR updated_at > sqlc.narg(updated_after))
ORDER BY updated_at DESC, id DESC
LIMIT sqlc.arg(page_limit);

-- name: GetEntry :one
SELECT * FROM entries
WHERE id = $1 AND user_id = $2;

-- name: GetEntriesByIDs :many
SELECT * FROM entries
WHERE user_id = sqlc.arg(user_id) AND id = ANY(sqlc.arg(ids)::uuid[]);

-- name: CreateEntry :one
INSERT INTO entries (
    id, user_id, project_id, kind, encrypted_blob, wrapped_item_key,
    title_hash, domain_hash, has_totp, is_favorite
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING *;

-- name: UpdateEntry :one
UPDATE entries
SET project_id       = $3,
    kind             = $4,
    encrypted_blob   = $5,
    wrapped_item_key = $6,
    title_hash       = $7,
    domain_hash      = $8,
    has_totp         = $9,
    is_favorite      = $10,
    version          = version + 1,
    updated_at       = now()
WHERE id = $1 AND user_id = $2 AND version = sqlc.arg(expected_version)
RETURNING *;

-- name: DeleteEntry :execrows
DELETE FROM entries
WHERE id = $1 AND user_id = $2;

-- name: ToggleFavorite :one
UPDATE entries SET is_favorite = $3, updated_at = now()
WHERE id = $1 AND user_id = $2
RETURNING *;

-- name: CountEntriesByProject :one
SELECT count(*) FROM entries
WHERE user_id = $1 AND project_id = $2;

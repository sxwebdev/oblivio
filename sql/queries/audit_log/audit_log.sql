-- name: AppendAuditEntry :one
INSERT INTO audit_log (
    user_id, action, target_id, ip, user_agent, metadata, prev_hash, self_hash
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: ListAuditEntries :many
SELECT *
FROM audit_log
WHERE user_id = $1
  AND (sqlc.narg(action_filter)::audit_action IS NULL OR action = sqlc.narg(action_filter))
  AND (sqlc.narg(from_time)::timestamptz IS NULL OR created_at >= sqlc.narg(from_time))
  AND (sqlc.narg(to_time)::timestamptz   IS NULL OR created_at <= sqlc.narg(to_time))
  AND (sqlc.narg(cursor_id)::bigint      IS NULL OR id < sqlc.narg(cursor_id))
ORDER BY id DESC
LIMIT sqlc.arg(page_limit);

-- name: GetAuditChainHead :one
SELECT id, self_hash FROM audit_log ORDER BY id DESC LIMIT 1;

-- name: GetAuditByID :one
SELECT * FROM audit_log WHERE id = $1;

-- name: ListAuditFromID :many
SELECT * FROM audit_log WHERE id > $1 ORDER BY id ASC LIMIT $2;

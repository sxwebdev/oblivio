-- name: GetIdempotencyEntry :one
SELECT * FROM idempotency_keys
WHERE user_id = $1 AND key = $2 AND expires_at > now();

-- name: InsertIdempotencyEntry :exec
INSERT INTO idempotency_keys (
    user_id, key, procedure, request_hash,
    response_status, response_body, expires_at
) VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: DeleteExpiredIdempotencyEntries :execrows
DELETE FROM idempotency_keys WHERE expires_at <= now();

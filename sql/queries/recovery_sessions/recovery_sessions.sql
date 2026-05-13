-- name: InsertRecoverySession :one
INSERT INTO recovery_sessions (id, user_id, email, expires_at)
VALUES ($1, $2, $3, $4)
RETURNING id;

-- name: GetRecoverySession :one
SELECT * FROM recovery_sessions WHERE id = $1;

-- name: DeleteRecoverySession :execrows
DELETE FROM recovery_sessions WHERE id = $1;

-- name: TakeRecoverySession :one
DELETE FROM recovery_sessions
WHERE id = $1
RETURNING *;

-- name: DeleteExpiredRecoverySessions :execrows
DELETE FROM recovery_sessions WHERE expires_at <= now();

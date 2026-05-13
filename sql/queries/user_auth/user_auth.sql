-- name: GetUserAuth :one
SELECT * FROM user_auth WHERE user_id = $1;

-- name: UpsertUserAuth :exec
INSERT INTO user_auth (user_id, auth_key_hash)
VALUES ($1, $2)
ON CONFLICT (user_id) DO UPDATE
SET auth_key_hash   = EXCLUDED.auth_key_hash,
    failed_attempts = 0,
    locked_until    = NULL;

-- name: RecordFailedLogin :one
UPDATE user_auth
SET failed_attempts = failed_attempts + 1,
    locked_until    = CASE
        WHEN failed_attempts + 1 >= 5 THEN now() + interval '15 minutes'
        ELSE locked_until
    END
WHERE user_id = $1
RETURNING failed_attempts, locked_until;

-- name: ResetFailedLogin :exec
UPDATE user_auth
SET failed_attempts = 0,
    locked_until    = NULL
WHERE user_id = $1;

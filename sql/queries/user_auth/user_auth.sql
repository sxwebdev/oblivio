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
-- Bumps failed_attempts and (re-)arms locked_until whenever the count is at
-- or above the threshold AND no lock is currently active. Re-arming on every
-- post-threshold attempt (not only the exact 5th) means the account keeps
-- re-locking after each window expires, so brute-force stays bounded (H-1
-- fix). The "no active lock" guard means a trickle of bad attempts cannot
-- *extend* a lock that is already running — Authorize refuses before calling
-- this while locked, so in practice the counter sits at the threshold for the
-- whole window and re-locks on the first attempt after it lapses.
UPDATE user_auth
SET failed_attempts = failed_attempts + 1,
    locked_until    = CASE
        WHEN failed_attempts + 1 >= 5 AND (locked_until IS NULL OR locked_until <= now())
            THEN now() + interval '15 minutes'
        ELSE locked_until
    END
WHERE user_id = $1
RETURNING failed_attempts, locked_until;

-- name: RecordFailedRecovery :one
-- Recovery-specific failure counter so a brute-force of the recovery proof
-- is bounded independently of the password-lockout counter (M-9). Same
-- re-arming semantics as RecordFailedLogin: (re-)lock whenever the count is
-- at or above the threshold and no lock is currently active, so the account
-- keeps re-locking after each window lapses rather than only once. A longer
-- window (1 hour) is fine because recovery is a rarely-used flow.
UPDATE user_auth
SET recovery_failed_attempts = recovery_failed_attempts + 1,
    recovery_locked_until    = CASE
        WHEN recovery_failed_attempts + 1 >= 5 AND (recovery_locked_until IS NULL OR recovery_locked_until <= now())
            THEN now() + interval '1 hour'
        ELSE recovery_locked_until
    END
WHERE user_id = $1
RETURNING recovery_failed_attempts, recovery_locked_until;

-- name: ResetFailedRecovery :exec
UPDATE user_auth
SET recovery_failed_attempts = 0,
    recovery_locked_until    = NULL
WHERE user_id = $1;

-- name: ResetFailedLogin :exec
UPDATE user_auth
SET failed_attempts = 0,
    locked_until    = NULL
WHERE user_id = $1;

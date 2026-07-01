-- name: InsertMFAChallenge :one
INSERT INTO mfa_challenges (
    id, user_id, email, auth_key_ct,
    device_id, device_type, device_name,
    totp_required, webauthn_state, expires_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING id;

-- name: GetMFAChallenge :one
SELECT * FROM mfa_challenges WHERE id = $1;

-- name: DeleteMFAChallenge :execrows
DELETE FROM mfa_challenges WHERE id = $1;

-- name: TakeMFAChallenge :one
-- Atomic SELECT-and-delete so two concurrent CompleteMFA calls cannot both
-- claim the same challenge. The row is returned even if expired; the Go
-- caller checks expires_at and surfaces ErrChallengeExpired.
DELETE FROM mfa_challenges
WHERE id = $1
RETURNING *;

-- name: IncrementMFAFailedAttempts :one
-- Bumps failed_attempts. Returns the new count. The Go caller decides
-- whether to burn the row (DeleteMFAChallenge) when the threshold is hit.
UPDATE mfa_challenges
SET failed_attempts = failed_attempts + 1
WHERE id = $1
RETURNING failed_attempts;

-- name: DeleteExpiredMFAChallenges :execrows
DELETE FROM mfa_challenges WHERE expires_at <= now();

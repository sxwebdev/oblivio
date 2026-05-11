-- name: InsertEmailVerificationToken :exec
INSERT INTO email_verification_tokens (token_hash, user_id, purpose, expires_at)
VALUES ($1, $2, $3, $4);

-- name: ConsumeEmailVerificationToken :one
-- Atomically marks the token consumed and returns its user_id. Returns
-- pgx.ErrNoRows when the token is absent, expired or already used.
UPDATE email_verification_tokens
SET consumed_at = now()
WHERE token_hash = $1
  AND consumed_at IS NULL
  AND expires_at > now()
RETURNING user_id;

-- name: InvalidateActiveEmailVerificationTokens :execrows
-- Marks every still-active token for the user consumed. Run before
-- generating a fresh ResendVerification token so an attacker can't keep
-- exchange-stale links.
UPDATE email_verification_tokens
SET consumed_at = now()
WHERE user_id = $1 AND purpose = $2 AND consumed_at IS NULL;

-- name: DeleteExpiredEmailVerificationTokens :execrows
DELETE FROM email_verification_tokens
WHERE expires_at <= now() AND (consumed_at IS NULL OR consumed_at <= now() - interval '7 days');

-- name: GetUserVault :one
SELECT * FROM user_vault WHERE user_id = $1;

-- name: CreateUserVault :exec
INSERT INTO user_vault (
    user_id, verifier, wrapped_vault_key,
    recovery_salt, recovery_wrapped_vault_key, recovery_proof_hash
) VALUES ($1, $2, $3, $4, $5, $6);

-- name: UpdateUserVaultPassword :exec
UPDATE user_vault
SET verifier          = $2,
    wrapped_vault_key = $3,
    vault_key_version = vault_key_version + 1
WHERE user_id = $1;

-- Recovery: rotate verifier/wrapped_vault_key and stamp recovery_used_at.
-- The recovery-related material (salt + wrapped) stays put so the same
-- recovery code can still be used (the client should generate a new one
-- after a successful recovery, but that is a UX nicety — not enforced).
-- name: CompleteRecovery :exec
UPDATE user_vault
SET verifier          = $2,
    wrapped_vault_key = $3,
    vault_key_version = vault_key_version + 1,
    recovery_used_at  = now()
WHERE user_id = $1;

-- WebAuthn registration challenges have no auth_key (the ceremony is run by
-- an already-authenticated user, not as part of a login). The mfa_store
-- code path already passes nil ciphertext for that case; we relax the
-- column's NOT NULL constraint to match that intent. Login-flow challenges
-- continue to carry the encrypted auth_key — application logic enforces
-- presence at use time (materialise() returns nil AuthKey only when the
-- column is genuinely NULL).
ALTER TABLE mfa_challenges ALTER COLUMN auth_key_ct DROP NOT NULL;

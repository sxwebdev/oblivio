-- Per-user pepper for the blind-index HKDF derivation.
-- Plan §4.4 / §6.4: without a per-user pepper, a leaked K_blind would let an
-- attacker confirm popular titles/domains via dictionary attack. The pepper
-- is generated client-side at registration and stored alongside salt_user.
-- It is non-secret in the sense that the server holds it, but is required
-- (alongside vault_key) to materialise K_blind.
--
-- Existing rows (dev only — no prod users) are seeded with random bytes so
-- the column can be NOT NULL. After this migration, existing entries' blind
-- hashes are stale (computed without pepper, info=v1) — clients are expected
-- to re-seal their data on next vault unlock. Production-style migrations
-- would need an explicit re-encryption job; we don't have prod users.

ALTER TABLE user_kdf_params
    ADD COLUMN blind_pepper BYTEA;

UPDATE user_kdf_params
SET blind_pepper = gen_random_bytes(16)
WHERE blind_pepper IS NULL;

ALTER TABLE user_kdf_params
    ALTER COLUMN blind_pepper SET NOT NULL;

-- Sprint 4: the audit chain's self_hash includes user_id, so the
-- ON DELETE SET NULL behaviour defined in migration 004 would silently
-- invalidate every prior row's hash when an account is crypto-shredded.
-- We drop the foreign key but keep the user_id column — it is now an
-- attribution UUID without referential integrity, which is what the
-- hash-chain requires to remain self-consistent across account deletions.
ALTER TABLE audit_log DROP CONSTRAINT audit_log_user_id_fkey;

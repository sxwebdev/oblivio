-- Reverting requires every existing row to have a non-NULL auth_key_ct,
-- which is not generally true (WebAuthn registration challenges insert
-- NULL). Drop any in-flight WebAuthn challenges first so the constraint
-- can re-attach without losing referential integrity.
DELETE FROM mfa_challenges WHERE auth_key_ct IS NULL;
ALTER TABLE mfa_challenges ALTER COLUMN auth_key_ct SET NOT NULL;

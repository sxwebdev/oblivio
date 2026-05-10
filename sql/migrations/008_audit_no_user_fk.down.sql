-- Re-create the FK. Note: rows with dangling user_id values (i.e. records
-- written for accounts deleted while the FK was absent) will block the
-- migration. Manual cleanup may be required to roll back in production.
ALTER TABLE audit_log
    ADD CONSTRAINT audit_log_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;

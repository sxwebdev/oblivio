-- Revert 013_security_hardening.up.sql.

CREATE OR REPLACE FUNCTION app_current_user_id() RETURNS UUID
    LANGUAGE plpgsql STABLE
AS $$
BEGIN
    RETURN current_setting('app.current_user_id', true)::uuid;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$;

DROP POLICY IF EXISTS audit_log_immutable_no_delete ON audit_log;
DROP POLICY IF EXISTS audit_log_immutable_no_update ON audit_log;

ALTER TABLE user_auth
    DROP COLUMN IF EXISTS recovery_locked_until,
    DROP COLUMN IF EXISTS recovery_failed_attempts;

ALTER TABLE mfa_challenges
    DROP COLUMN IF EXISTS failed_attempts;

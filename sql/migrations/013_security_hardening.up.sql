-- Security hardening rollup. See plan: swirling-stirring-frost.md.
--
-- This migration adds defensive columns and policies for several fixes
-- that ship as one rollup:
--   * C-1: per-MFA-challenge failed-attempt counter so CompleteMFA can
--     burn a challenge after too many wrong codes (TOTP/WebAuthn brute
--     force defence).
--   * M-9: separate failure counter and lockout for the recovery proof
--     so brute-forcing the recovery code is bounded.
--   * F-10: explicit deny policies for UPDATE/DELETE on audit_log so a
--     future `FOR ALL` policy cannot accidentally widen the surface.
--   * F-11: narrow the exception caught by app_current_user_id() to the
--     expected cast failure only.
--
-- NOTE: M-6 (source-IP / bind-token binding on recovery_sessions and
-- mfa_challenges) is intentionally NOT in this rollup. It requires request
-- IP plumbing into the handlers (absent today) and, for the bind-token, a
-- wire-protocol field the client round-trips. Shipping the columns without
-- that wiring would advertise a control the code never enforces, so they
-- are deferred to a dedicated change.

-- Forensic events. login_failed / mfa_failed / recovery_failed surface
-- slow-brute-force attempts in the chain instead of only success records.
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'login_failed';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'mfa_failed';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'recovery_failed';

ALTER TABLE mfa_challenges
    ADD COLUMN failed_attempts INT NOT NULL DEFAULT 0;

ALTER TABLE user_auth
    ADD COLUMN recovery_failed_attempts INT         NOT NULL DEFAULT 0,
    ADD COLUMN recovery_locked_until    TIMESTAMPTZ;

CREATE POLICY audit_log_immutable_no_update ON audit_log
    FOR UPDATE
    USING (false)
    WITH CHECK (false);

CREATE POLICY audit_log_immutable_no_delete ON audit_log
    FOR DELETE
    USING (false);

CREATE OR REPLACE FUNCTION app_current_user_id() RETURNS UUID
    LANGUAGE plpgsql STABLE
AS $$
BEGIN
    RETURN current_setting('app.current_user_id', true)::uuid;
EXCEPTION WHEN invalid_text_representation THEN
    RETURN NULL;
END;
$$;

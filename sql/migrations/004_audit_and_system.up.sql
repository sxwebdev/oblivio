CREATE TYPE audit_action AS ENUM (
    'register','login','logout','refresh','password_change',
    'recovery_start','recovery_complete',
    'webauthn_register','webauthn_remove','totp_enable','totp_disable',
    'project_create','project_update','project_delete',
    'entry_create','entry_update','entry_view','entry_delete',
    'session_terminate','account_delete',
    -- Sprint F: email verification flow.
    'email_verify','email_resend'
);

-- Append-only hash-chained audit log. The chain head is mirrored into
-- system_state.audit_chain_head; a periodic job re-walks the chain and
-- alarms on mismatch (Sprint 4).
-- audit_log.user_id is intentionally NOT a foreign key. The hash chain's
-- self_hash includes user_id as part of canonical row data, so an
-- ON DELETE SET NULL would silently break the chain at the moment of
-- account deletion. The column stays as an attribution UUID without
-- referential integrity (validated only at write time by the writer).
CREATE TABLE audit_log (
    id          BIGSERIAL PRIMARY KEY,
    user_id     UUID,
    action      audit_action NOT NULL,
    target_id   UUID,
    ip          INET,
    user_agent  TEXT,
    metadata    JSONB,
    prev_hash   BYTEA NOT NULL,
    self_hash   BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_user_id ON audit_log(user_id, created_at DESC);
CREATE INDEX idx_audit_action  ON audit_log(action, created_at DESC);

CREATE TABLE system_state (
    key        TEXT PRIMARY KEY,
    value      JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed the chain head as 32 zero bytes; chain.go enforces this invariant
-- on first append.
INSERT INTO system_state (key, value)
VALUES ('audit_chain_head', '"0000000000000000000000000000000000000000000000000000000000000000"'::jsonb)
ON CONFLICT (key) DO NOTHING;

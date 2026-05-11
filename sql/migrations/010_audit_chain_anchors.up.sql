-- Audit-chain external anchor (plan §17.4).
--
-- The hash chain in audit_log + system_state.audit_chain_head defends
-- against accidental tampering and from attackers who write through the
-- application layer. It does NOT defend against an attacker with direct DB
-- access who rewrites both the chain rows AND the head value.
--
-- This table holds periodic signatures over the head, produced by a key
-- the attacker is unlikely to also possess (Vault transit, or an Ed25519
-- key loaded from a sealed env var). A verifier then walks the chain and
-- compares the current head with the most recent signed anchor — any
-- divergence is detected even when both the rows and the head value were
-- rewritten coherently in the DB.

CREATE TABLE audit_chain_anchors (
    id          BIGSERIAL PRIMARY KEY,
    head        BYTEA NOT NULL,
    signature   BYTEA NOT NULL,
    signed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    signer_id   TEXT NOT NULL
);
CREATE INDEX idx_audit_chain_anchors_signed_at ON audit_chain_anchors(signed_at DESC);

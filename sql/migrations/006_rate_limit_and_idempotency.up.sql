-- Idempotency: client supplies a unique key per mutating request; the
-- server stores the response so retries return the same body and never
-- create a duplicate record. Entries expire after 24h and are reaped
-- by jobs/idempotency_gc.
--
-- Note: an earlier draft of the plan (§6.6) called for a token-bucket
-- table here too. The Sprint-4 limiter is in-memory (see
-- internal/api/middleware/rate_limit.go); the table was unused so we
-- dropped it from this migration. Re-introduce only if a multi-replica
-- deployment needs cross-process bucket coordination.
CREATE TABLE idempotency_keys (
    key              TEXT NOT NULL,
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    procedure        TEXT NOT NULL,
    request_hash     BYTEA NOT NULL,
    response_status  INT  NOT NULL,
    response_body    BYTEA NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at       TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, key)
);
CREATE INDEX idx_idempotency_expires ON idempotency_keys(expires_at);

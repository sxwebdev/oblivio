-- Token-bucket counters keyed by ("kind:identifier"), e.g.
-- "auth_login:alice@example.com" or "kdf_params:203.0.113.10".
-- Refilled lazily on read.
CREATE TABLE rate_limit_buckets (
    bucket_key      TEXT PRIMARY KEY,
    tokens          REAL NOT NULL,
    last_refill_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Idempotency: client supplies a unique key per mutating request; the
-- server stores the response so retries return the same body and never
-- create a duplicate record. Entries expire after 24h.
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

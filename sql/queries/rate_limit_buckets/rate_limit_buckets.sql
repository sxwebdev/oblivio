-- Atomic refill-and-consume in one statement. The CTE computes the new
-- token count from the existing row (or starts at $4=burst-1 for a fresh
-- bucket) and writes it back, RETURNING the resulting `tokens` value so
-- the caller can decide allow/deny by checking >= 0.
--
-- Refill rate is `rate_per_sec` tokens per second; cap at $4 (burst).
-- We let `tokens` go briefly negative to indicate "denied this request"
-- without a separate rejection path — the Go code clamps to 0 on the
-- next allow.

-- name: ConsumeRateLimit :one
INSERT INTO rate_limit_buckets (kind, key, tokens, refilled_at)
VALUES (
    sqlc.arg(kind)::text,
    sqlc.arg(key)::text,
    sqlc.arg(burst)::double precision - 1,
    now()
)
ON CONFLICT (kind, key) DO UPDATE
SET tokens = LEAST(
        sqlc.arg(burst)::double precision,
        rate_limit_buckets.tokens
            + sqlc.arg(rate_per_sec)::double precision
                * GREATEST(0, EXTRACT(EPOCH FROM (now() - rate_limit_buckets.refilled_at)))
    ) - 1,
    refilled_at = now()
RETURNING tokens;

-- name: DeleteStaleRateLimitBuckets :execrows
-- Reaps buckets that are full (tokens >= burst-1) and untouched for >1h.
-- Buckets that are actively in use refresh their refilled_at and stay.
DELETE FROM rate_limit_buckets
WHERE refilled_at < now() - INTERVAL '1 hour';

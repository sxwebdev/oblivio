-- name: GetBucket :one
SELECT * FROM rate_limit_buckets WHERE bucket_key = $1;

-- name: UpsertBucket :exec
INSERT INTO rate_limit_buckets (bucket_key, tokens, last_refill_at)
VALUES ($1, $2, $3)
ON CONFLICT (bucket_key) DO UPDATE
SET tokens = EXCLUDED.tokens, last_refill_at = EXCLUDED.last_refill_at;

-- name: DeleteStaleBuckets :execrows
DELETE FROM rate_limit_buckets WHERE last_refill_at < $1;

-- name: UpdateDelegationOrderStatus :one
UPDATE delegation_orders
SET status = $2, provider_order_id = $3, error_message = $4, updated_at = now()
WHERE id = $1
RETURNING *;

-- name: UpdateDelegationOrderResult :one
UPDATE delegation_orders
SET status = sqlc.arg('status'),
    provider = sqlc.arg('provider'),
    provider_order_id = sqlc.narg('provider_order_id'),
    error_message = sqlc.narg('error_message'),
    cost_trx = sqlc.narg('cost_trx'),
    tx_hash = sqlc.narg('tx_hash'),
    delivered_amount = sqlc.narg('delivered_amount'),
    updated_at = now()
WHERE id = sqlc.arg('id')
RETURNING *;

-- name: FinalizePendingOrder :one
UPDATE delegation_orders
SET status = sqlc.arg('status'),
    error_message = sqlc.narg('error_message'),
    cost_trx = COALESCE(sqlc.narg('cost_trx'), cost_trx),
    tx_hash = COALESCE(sqlc.narg('tx_hash'), tx_hash),
    delivered_amount = COALESCE(sqlc.narg('delivered_amount'), delivered_amount),
    updated_at = now()
WHERE id = sqlc.arg('id')
RETURNING *;

-- name: ListPendingProviderOrders :many
SELECT *
FROM delegation_orders
WHERE status = 'processing'
  AND tx_hash IS NULL
  AND provider = $1
  AND created_at > now() - $2::interval
ORDER BY created_at ASC;

-- name: TimeoutStalePendingOrders :exec
UPDATE delegation_orders
SET status = 'failed',
    error_message = 'polling timeout',
    updated_at = now()
WHERE status = 'processing'
  AND tx_hash IS NULL
  AND provider = $1
  AND created_at <= now() - $2::interval;

-- name: Create :one
INSERT INTO delegation_orders (wallet_id, target_address, resource_type, amount, period, status, provider, provider_order_id, error_message, is_manual, created_at, cost_trx, tx_hash, delivered_amount)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now(), $11, $12, $13)
	RETURNING *;

-- name: Find :many
SELECT * FROM delegation_orders ORDER BY created_at DESC LIMIT $1 OFFSET $2;

-- name: GetByID :one
SELECT * FROM delegation_orders WHERE id=$1 LIMIT 1;

-- name: Total :one
SELECT count(1) as total FROM delegation_orders;

-- name: Update :one
UPDATE delegation_orders
	SET wallet_id=$1, target_address=$2, resource_type=$3, amount=$4, period=$5, status=$6, provider=$7, provider_order_id=$8, error_message=$9, is_manual=$10, updated_at=now(), cost_trx=$11, tx_hash=$12, delivered_amount=$13
WHERE id=$14
	RETURNING *;

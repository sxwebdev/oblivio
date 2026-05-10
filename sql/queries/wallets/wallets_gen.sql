-- name: Create :one
INSERT INTO wallets (name, address, blockchain, energy_threshold, bandwidth_threshold, energy_delegate_amount, bandwidth_delegate_amount, energy_period, bandwidth_period, is_active, current_energy, current_bandwidth, current_balance, last_checked_at, created_at)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, now())
	RETURNING *;

-- name: Delete :exec
DELETE FROM wallets WHERE id=$1;

-- name: Find :many
SELECT * FROM wallets ORDER BY created_at DESC LIMIT $1 OFFSET $2;

-- name: GetByID :one
SELECT * FROM wallets WHERE id=$1 LIMIT 1;

-- name: Total :one
SELECT count(1) as total FROM wallets;

-- name: Update :one
UPDATE wallets
	SET name=$1, address=$2, blockchain=$3, energy_threshold=$4, bandwidth_threshold=$5, energy_delegate_amount=$6, bandwidth_delegate_amount=$7, energy_period=$8, bandwidth_period=$9, is_active=$10, current_energy=$11, current_bandwidth=$12, current_balance=$13, last_checked_at=$14, updated_at=now()
WHERE id=$15
	RETURNING *;

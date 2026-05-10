-- name: FindActiveWallets :many
SELECT * FROM wallets WHERE is_active = TRUE ORDER BY created_at DESC;

-- name: UpdateResources :one
UPDATE wallets
  SET current_energy=$1,
      current_bandwidth=$2,
      current_balance=$3,
      last_checked_at=now(),
      updated_at=now()
WHERE id=$4
  RETURNING *;

-- name: Find :many
SELECT * FROM settings;

-- name: GetByKey :one
SELECT * FROM settings WHERE key=$1 LIMIT 1;

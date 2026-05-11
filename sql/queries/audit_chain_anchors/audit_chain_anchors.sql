-- name: InsertAuditChainAnchor :one
INSERT INTO audit_chain_anchors (head, signature, signer_id)
VALUES ($1, $2, $3)
RETURNING id;

-- name: GetLatestAuditChainAnchor :one
SELECT * FROM audit_chain_anchors
ORDER BY signed_at DESC
LIMIT 1;

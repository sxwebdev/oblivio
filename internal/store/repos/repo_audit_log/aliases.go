package repo_audit_log

import "github.com/sxwebdev/oblivio/internal/models"

// NullAuditAction aliases the central nullable-enum wrapper so the sqlc-generated
// code in this package can compile without re-declaring it.
type NullAuditAction = models.NullAuditAction

// Hand-written extensions to the pgxgen-generated audit action enum.
// pgxgen only picks up ENUM values declared in the original CREATE TYPE
// statement, so values added via `ALTER TYPE ... ADD VALUE` (e.g.
// migration 014) need to be exposed manually. Adding a new value here
// has no effect on the database — the migration must accompany it.

package models

const (
	// AuditActionAccountDeleteAttemptFailed is appended by
	// VaultService.DeleteMe before returning Unauthenticated when any
	// required factor (auth_key, TOTP, passkey assertion) fails. The
	// audit chain therefore records every probe of the crypto-shred
	// path, not just successful deletions.
	AuditActionAccountDeleteAttemptFailed AuditAction = "account_delete_attempt_failed"
)

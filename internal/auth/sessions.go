package auth

import (
	"crypto/sha256"

	"github.com/google/uuid"
)

// SessionData is the per-session payload carried inside access and refresh
// tokens. The session_id binds a token pair to a specific row in
// auth_sessions so the row can be looked up and revoked atomically.
type SessionData struct {
	SessionID  uuid.UUID `json:"session_id"`
	DeviceID   string    `json:"device_id"`
	DeviceType string    `json:"device_type"`
}

// TokenHash returns the SHA-256 of the signed token. We store hashes (not raw
// tokens) in auth_sessions so a database compromise does not yield reusable
// credentials.
func TokenHash(signedToken string) []byte {
	sum := sha256.Sum256([]byte(signedToken))
	return sum[:]
}

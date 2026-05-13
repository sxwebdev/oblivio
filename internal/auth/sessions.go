package auth

import "github.com/google/uuid"

// SessionData is the per-session payload carried inside access and refresh
// tokens. The session_id binds a token pair to a specific row in
// auth_sessions so the row can be looked up and revoked atomically.
type SessionData struct {
	SessionID  uuid.UUID `json:"session_id"`
	DeviceID   string    `json:"device_id"`
	DeviceType string    `json:"device_type"`
}

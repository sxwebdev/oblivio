package webauthn

import (
	"github.com/sxwebdev/oblivio/internal/auth/wauser"
	"github.com/sxwebdev/oblivio/internal/models"
)

// newUser is a thin re-export of wauser.New kept so the rest of this
// package stays readable. The shared adapter lives in internal/auth/wauser.
func newUser(u *models.User, creds []*models.UserWebauthnCredential) *wauser.User {
	return wauser.New(u, creds)
}

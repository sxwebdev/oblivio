package auth

import (
	"github.com/awnumar/memguard"

	"github.com/sxwebdev/oblivio/internal/auth"
	"github.com/sxwebdev/oblivio/internal/auth/wauser"
	"github.com/sxwebdev/oblivio/internal/models"
)

// buildWebAuthnUser is a thin re-export of wauser.New kept here so call
// sites in this package don't have to import a deeply-named symbol.
func buildWebAuthnUser(u *models.User, creds []*models.UserWebauthnCredential) *wauser.User {
	return wauser.New(u, creds)
}

// openLoginTOTP decrypts a login-TOTP envelope and returns the plaintext
// inside a memguard.LockedBuffer. The caller MUST `Destroy()` the buffer
// (typically via defer) immediately after validating the code. The K_login_totp
// material is wiped by OpenLoginTOTPSecret before this function returns.
func openLoginTOTP(authKey, blob []byte) (*memguard.LockedBuffer, error) {
	return auth.OpenLoginTOTPSecret(authKey, blob)
}

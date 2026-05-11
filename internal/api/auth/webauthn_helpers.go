package auth

import (
	"github.com/sxwebdev/oblivio/internal/auth"
	"github.com/sxwebdev/oblivio/internal/auth/wauser"
	srvcrypto "github.com/sxwebdev/oblivio/internal/crypto"
	"github.com/sxwebdev/oblivio/internal/models"
)

// buildWebAuthnUser is a thin re-export of wauser.New kept here so call
// sites in this package don't have to import a deeply-named symbol.
func buildWebAuthnUser(u *models.User, creds []*models.UserWebauthnCredential) *wauser.User {
	return wauser.New(u, creds)
}

// openLoginTOTP decrypts a login-TOTP envelope using K_login_totp derived
// from the supplied auth_key. The intermediate key buffer is destroyed
// before the function returns.
func openLoginTOTP(authKey, blob []byte) (string, error) {
	keyBuf, err := auth.DeriveLoginTOTPKey(authKey)
	if err != nil {
		return "", err
	}
	defer keyBuf.Destroy()
	pt, err := srvcrypto.AESGCMOpen(keyBuf.Bytes(), blob, []byte(auth.LoginTOTPAAD))
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

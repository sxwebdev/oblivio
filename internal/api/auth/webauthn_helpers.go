package auth

import (
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/sxwebdev/oblivio/internal/auth"
	srvcrypto "github.com/sxwebdev/oblivio/internal/crypto"
	"github.com/sxwebdev/oblivio/internal/models"
)

// loginUser adapts an oblivio user + credentials to the webauthn.User
// interface for go-webauthn. Duplicated from the webauthn package because
// the AuthService also needs to drive login ceremonies and we want to
// avoid an import cycle.
type loginUser struct {
	id          uuid.UUID
	name        string
	displayName string
	credentials []webauthn.Credential
}

func buildWebAuthnUser(u *models.User, creds []*models.UserWebauthnCredential) *loginUser {
	out := &loginUser{
		id:          u.ID,
		name:        u.Email,
		displayName: u.Email,
		credentials: make([]webauthn.Credential, 0, len(creds)),
	}
	for _, c := range creds {
		var aaguid []byte
		if len(c.Aaguid) > 0 {
			aaguid = c.Aaguid
		}
		out.credentials = append(out.credentials, webauthn.Credential{
			ID:        c.CredentialID,
			PublicKey: c.PublicKey,
			Authenticator: webauthn.Authenticator{
				AAGUID:    aaguid,
				SignCount: uint32(c.SignCount), //nolint:gosec
			},
		})
	}
	return out
}

func (u *loginUser) WebAuthnID() []byte {
	b, _ := u.id.MarshalBinary()
	return b
}
func (u *loginUser) WebAuthnName() string                       { return u.name }
func (u *loginUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *loginUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

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

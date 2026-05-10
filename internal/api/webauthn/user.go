package webauthn

import (
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/sxwebdev/oblivio/internal/models"
)

// webauthnUser adapts an oblivio user + its registered credentials to the
// webauthn.User interface go-webauthn expects.
type webauthnUser struct {
	id          uuid.UUID
	name        string
	displayName string
	credentials []webauthn.Credential
}

func newUser(u *models.User, creds []*models.UserWebauthnCredential) *webauthnUser {
	out := &webauthnUser{
		id:          u.ID,
		name:        u.Email,
		displayName: u.Email,
	}
	out.credentials = make([]webauthn.Credential, 0, len(creds))
	for _, c := range creds {
		var aaguid []byte
		if len(c.Aaguid) > 0 {
			aaguid = c.Aaguid
		}
		wc := webauthn.Credential{
			ID:        c.CredentialID,
			PublicKey: c.PublicKey,
			Authenticator: webauthn.Authenticator{
				AAGUID:    aaguid,
				SignCount: uint32(c.SignCount), //nolint:gosec // truncation acceptable, sign_count is small
			},
		}
		out.credentials = append(out.credentials, wc)
	}
	return out
}

func (u *webauthnUser) WebAuthnID() []byte {
	b, _ := u.id.MarshalBinary()
	return b
}
func (u *webauthnUser) WebAuthnName() string                       { return u.name }
func (u *webauthnUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

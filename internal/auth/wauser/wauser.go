// Package wauser hosts a single shared adapter from the oblivio user +
// stored credentials to the webauthn.User interface go-webauthn expects.
//
// Without this package the adapter would be duplicated across every
// service that drives a WebAuthn ceremony (auth, webauthn, login_totp).
// Three copies of the same struct were drifting apart by Sprint 4 — this
// is the canonical version.
package wauser

import (
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/sxwebdev/oblivio/internal/models"
)

// User is the adapter type. Construct via New.
type User struct {
	id          uuid.UUID
	name        string
	displayName string
	credentials []webauthn.Credential
}

// New returns a webauthn.User backed by an oblivio user row + its stored
// credentials. The user's email is used as both name and display name —
// callers can wrap and override if a richer profile becomes available.
func New(u *models.User, creds []*models.UserWebauthnCredential) *User {
	out := &User{
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

// FromIdentity is the variant used when the caller doesn't have a full
// *models.User on hand (e.g. login_totp passing only id+email through
// an MFA challenge). Behaviour is otherwise identical to New.
func FromIdentity(id uuid.UUID, email string, creds []*models.UserWebauthnCredential) *User {
	return New(&models.User{ID: id, Email: email}, creds)
}

func (u *User) WebAuthnID() []byte {
	b, _ := u.id.MarshalBinary()
	return b
}
func (u *User) WebAuthnName() string                       { return u.name }
func (u *User) WebAuthnDisplayName() string                { return u.displayName }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

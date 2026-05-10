// Server-side login TOTP helpers (plan §5.3).
//
// The TOTP secret protecting the user's account login is encrypted client-side
// under K_login_totp = HKDF(auth_key, "oblivio/login-totp/v1"). The server
// receives `auth_key` on every Authorize call, derives K_login_totp into a
// memguard.LockedBuffer, decrypts the stored secret, validates the supplied
// code, and wipes the buffer immediately. The plaintext TOTP secret is never
// persisted; auth_key is never persisted either, so a database leak alone
// cannot recover the secret.

package auth

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 mandates HMAC-SHA1 for authenticator-app compatibility.
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/hkdf"
)

// LoginTOTPInfo is the HKDF info string that derives the client/server
// TOTP-wrapping key from auth_key. Bumping this requires a migration.
const LoginTOTPInfo = "oblivio/login-totp/v1"

// LoginTOTPAAD is the AAD label baked into the AES-GCM envelope around the
// TOTP secret. It is identical on the client (frontend/packages/crypto/totp.ts)
// and the server. Treat as a versioning hook — if we ever change envelopes,
// bump the label and migrate atomically.
const LoginTOTPAAD = "oblivio/login-totp/v1"

// DeriveLoginTOTPKey returns K_login_totp inside a memguard.LockedBuffer.
// Call Destroy on the buffer as soon as the caller no longer needs the key.
func DeriveLoginTOTPKey(authKey []byte) (*memguard.LockedBuffer, error) {
	if len(authKey) == 0 {
		return nil, errors.New("login_totp: empty auth_key")
	}
	r := hkdf.New(sha256.New, authKey, nil, []byte(LoginTOTPInfo))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("login_totp: hkdf: %w", err)
	}
	// NewBufferFromBytes wipes the source slice after copying so we don't
	// leave a plaintext duplicate on the heap.
	return memguard.NewBufferFromBytes(out), nil
}

// ValidateTOTPCode checks `code` against `secretBase32` using RFC 6238 with
// a ±1 step tolerance (30s before/after current). The default step is 30s
// and digits=6 — both standard for authenticator apps.
//
// Returns nil on match, an error on mismatch. The error message is generic
// to avoid leaking timing details about which step matched.
func ValidateTOTPCode(secretBase32, code string) error {
	code = strings.TrimSpace(code)
	if len(code) == 0 {
		return errors.New("login_totp: empty code")
	}
	// Allow ±1 step (30s) of clock skew.
	now := time.Now().UTC().Unix()
	step := int64(30)
	cur := now / step
	secret, err := decodeBase32Secret(secretBase32)
	if err != nil {
		return fmt.Errorf("login_totp: decode secret: %w", err)
	}
	for delta := int64(-1); delta <= 1; delta++ {
		want := generateHOTP(secret, uint64(cur+delta), 6)
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return nil
		}
	}
	return errors.New("login_totp: invalid code")
}

func decodeBase32Secret(s string) ([]byte, error) {
	// Normalise: drop spaces/dashes/padding, uppercase, then base32 decode
	// without padding.
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '-', '=':
			return -1
		default:
			return r
		}
	}, s)
	cleaned = strings.ToUpper(cleaned)
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(cleaned)
}

// generateHOTP implements RFC 4226 §5.3 (HMAC-SHA1 + dynamic truncation).
func generateHOTP(secret []byte, counter uint64, digits int) string {
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(ctr[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := (uint32(sum[off]&0x7f) << 24) |
		(uint32(sum[off+1]&0xff) << 16) |
		(uint32(sum[off+2]&0xff) << 8) |
		uint32(sum[off+3]&0xff)
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	v %= mod
	return fmt.Sprintf("%0*d", digits, v)
}

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

	srvcrypto "github.com/sxwebdev/oblivio/internal/crypto"
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

// OpenLoginTOTPSecret decrypts a stored login-TOTP envelope and returns the
// plaintext secret wrapped in a memguard.LockedBuffer. The caller MUST
// `Destroy()` the buffer (typically via defer) as soon as the secret has
// been validated; the plaintext lives in locked memory until then so it
// is excluded from coredumps and swap.
//
// Compared to the older string-returning helper this version eliminates the
// `string(plaintext)` conversion that left an immutable, unwipeable copy of
// the secret on the heap (see plan §17.5 — memguard coverage).
func OpenLoginTOTPSecret(authKey, blob []byte) (*memguard.LockedBuffer, error) {
	keyBuf, err := DeriveLoginTOTPKey(authKey)
	if err != nil {
		return nil, err
	}
	defer keyBuf.Destroy()
	pt, err := srvcrypto.AESGCMOpen(keyBuf.Bytes(), blob, []byte(LoginTOTPAAD))
	if err != nil {
		return nil, err
	}
	// NewBufferFromBytes copies the source and zeroes the original — the
	// returned buffer is the only live copy of the plaintext.
	return memguard.NewBufferFromBytes(pt), nil
}

// ValidateTOTPCodeBytes is the byte-slice variant of ValidateTOTPCode. It
// avoids the `string(secret)` round-trip so callers operating on a memguard
// buffer don't leak an immutable plaintext copy onto the heap. The slice is
// expected to be a base32-encoded TOTP secret as produced by authenticator
// apps and matches the wire format the client uploaded at Setup.
func ValidateTOTPCodeBytes(secretBase32, code []byte) error {
	if len(code) == 0 {
		return errors.New("login_totp: empty code")
	}
	now := time.Now().UTC().Unix()
	step := int64(30)
	cur := now / step
	secret, err := decodeBase32SecretBytes(secretBase32)
	if err != nil {
		return fmt.Errorf("login_totp: decode secret: %w", err)
	}
	defer func() {
		for i := range secret {
			secret[i] = 0
		}
	}()
	for delta := int64(-1); delta <= 1; delta++ {
		want := generateHOTP(secret, uint64(cur+delta), 6)
		if subtle.ConstantTimeCompare([]byte(want), code) == 1 {
			return nil
		}
	}
	return errors.New("login_totp: invalid code")
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

// decodeBase32SecretBytes mirrors decodeBase32Secret but takes a byte slice
// so callers operating on memguard-wrapped plaintext don't need a
// `string(...)` conversion that lands an immutable copy on the heap.
func decodeBase32SecretBytes(b []byte) ([]byte, error) {
	cleaned := make([]byte, 0, len(b))
	for _, c := range b {
		switch c {
		case ' ', '-', '=':
			continue
		}
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		cleaned = append(cleaned, c)
	}
	out := make([]byte, base32.StdEncoding.WithPadding(base32.NoPadding).DecodedLen(len(cleaned)))
	n, err := base32.StdEncoding.WithPadding(base32.NoPadding).Decode(out, cleaned)
	if err != nil {
		return nil, err
	}
	return out[:n], nil
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

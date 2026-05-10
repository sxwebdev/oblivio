// Package auth implements server-side authentication primitives:
// Argon2id hashing of the client-supplied auth_key, token issuance via
// tokenmanager, and session persistence backed by auth_sessions.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params describes the server-side Argon2id parameters used to hash
// auth_key before storage. These are versioned in the PHC string and can be
// upgraded by rehashing during login.
type Argon2Params struct {
	T    uint32
	MKiB uint32
	P    uint8
}

const (
	argon2Version = argon2.Version
	saltLen       = 16
	keyLen        = 32
)

// HashAuthKey returns a PHC-encoded Argon2id hash of authKey using the given
// parameters and a freshly generated random salt.
func HashAuthKey(authKey []byte, p Argon2Params) (string, error) {
	if len(authKey) == 0 {
		return "", errors.New("empty auth key")
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("argon2: read salt: %w", err)
	}
	dk := argon2.IDKey(authKey, salt, p.T, p.MKiB, p.P, keyLen)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2Version, p.MKiB, p.T, p.P,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk),
	), nil
}

// VerifyAuthKey returns true when authKey matches the PHC-encoded hash.
// The comparison is constant-time. Returns an error only when the encoded
// string cannot be parsed.
func VerifyAuthKey(authKey []byte, encoded string) (bool, error) {
	p, salt, want, err := parsePHC(encoded)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey(authKey, salt, p.T, p.MKiB, p.P, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// parsePHC parses an Argon2id PHC string of the form
// $argon2id$v=19$m=<m>,t=<t>,p=<p>$<b64salt>$<b64hash>.
func parsePHC(s string) (Argon2Params, []byte, []byte, error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 {
		return Argon2Params{}, nil, nil, fmt.Errorf("argon2: invalid PHC parts=%d", len(parts))
	}
	if parts[1] != "argon2id" {
		return Argon2Params{}, nil, nil, fmt.Errorf("argon2: unsupported algorithm %q", parts[1])
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2Version {
		return Argon2Params{}, nil, nil, fmt.Errorf("argon2: unsupported version %q", parts[2])
	}

	var m, t uint32
	var p uint8
	kv := strings.Split(parts[3], ",")
	if len(kv) != 3 {
		return Argon2Params{}, nil, nil, fmt.Errorf("argon2: invalid params %q", parts[3])
	}
	for _, pair := range kv {
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			return Argon2Params{}, nil, nil, fmt.Errorf("argon2: invalid param %q", pair)
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return Argon2Params{}, nil, nil, fmt.Errorf("argon2: invalid param %q: %w", pair, err)
		}
		switch k {
		case "m":
			m = uint32(n)
		case "t":
			t = uint32(n)
		case "p":
			p = uint8(n)
		default:
			return Argon2Params{}, nil, nil, fmt.Errorf("argon2: unknown param %q", k)
		}
	}

	// Argon2id requires t≥1, p≥1 and m≥8*p (RFC 9106 §3.1). golang.org/x/crypto
	// panics otherwise, so any attacker-supplied PHC carrying zeroes must be
	// rejected here before it reaches IDKey.
	if t < 1 || p < 1 || m < 8*uint32(p) {
		return Argon2Params{}, nil, nil, fmt.Errorf("argon2: out-of-range params t=%d m=%d p=%d", t, m, p)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Argon2Params{}, nil, nil, fmt.Errorf("argon2: decode salt: %w", err)
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Argon2Params{}, nil, nil, fmt.Errorf("argon2: decode hash: %w", err)
	}
	// IDKey panics when keyLen < 4. Reject obviously-truncated hashes.
	if len(hash) < 4 {
		return Argon2Params{}, nil, nil, fmt.Errorf("argon2: hash too short: %d bytes", len(hash))
	}
	return Argon2Params{T: t, MKiB: m, P: p}, salt, hash, nil
}

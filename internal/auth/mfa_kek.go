package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/hkdf"

	"github.com/sxwebdev/oblivio/internal/crypto"
)

// MFAKEK is a 32-byte key-encryption-key used to wrap the auth_key bytes
// stored inside the Postgres-backed MFA challenge rows. The KEK never leaves
// memory and is held inside a memguard.LockedBuffer for the lifetime of the
// process.
//
// Why a KEK at all? Moving the MFA challenge from in-memory to Postgres
// widens the blast radius: a DB dump now contains the auth_key. Encrypting
// at rest under a process-local (or cluster-shared) KEK means the dump
// alone is useless — the attacker also needs the KEK material, which is
// either in process memory or in Vault.
//
// Key sourcing (in order of preference):
//
//  1. Vault transit-derived seed: when the operator runs more than one
//     server instance, they MUST provide a shared 32-byte seed via Vault
//     (or directly via env) so every instance derives the same KEK. The
//     constructor accepts the seed via `seed` argument.
//  2. OBLIVIO_MFA_KEK_SEED env var: 32+ bytes, hex or base64. Same role as
//     (1) — caller resolves the env var.
//  3. Per-instance random: when neither is supplied, a fresh 32 random
//     bytes are generated. Challenges are then bound to the instance that
//     created them; multi-instance deploys must enable sticky sessions on
//     the LB.
type MFAKEK struct {
	buf *memguard.LockedBuffer
	// instanceLocal records whether the KEK was generated locally (true)
	// or derived from a shared seed (false). Surfaced for ops logging.
	instanceLocal bool
}

// NewMFAKEK constructs a KEK. Resolution order:
//
//	if len(seed) > 0:   HKDF-SHA256(seed, info="oblivio/mfa-kek/v1") → 32-byte KEK (shared)
//	else:               crypto/rand 32 bytes (per-instance)
//
// `seed` may be any length ≥ 16 bytes when provided. The caller is
// responsible for wiping the seed slice after passing it in; we copy
// internally into a memguard buffer.
func NewMFAKEK(seed []byte) (*MFAKEK, error) {
	if len(seed) > 0 {
		if len(seed) < 16 {
			return nil, fmt.Errorf("mfa kek: seed must be at least 16 bytes, got %d", len(seed))
		}
		out := make([]byte, 32)
		r := hkdf.New(sha256.New, seed, nil, []byte("oblivio/mfa-kek/v1"))
		if _, err := io.ReadFull(r, out); err != nil {
			return nil, fmt.Errorf("mfa kek: hkdf: %w", err)
		}
		return &MFAKEK{
			buf:           memguard.NewBufferFromBytes(out),
			instanceLocal: false,
		}, nil
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("mfa kek: random: %w", err)
	}
	return &MFAKEK{
		buf:           memguard.NewBufferFromBytes(raw),
		instanceLocal: true,
	}, nil
}

// IsInstanceLocal reports whether this KEK was generated per-instance
// (not derived from a shared seed). The caller can use this to refuse to
// boot in multi-instance mode without a shared seed.
func (k *MFAKEK) IsInstanceLocal() bool {
	if k == nil {
		return true
	}
	return k.instanceLocal
}

// Seal encrypts plaintext under the KEK with AAD bound to the challenge id.
// The returned blob is the standard versioned envelope produced by
// internal/crypto.AESGCMSeal — `version(1) || nonce(12) || ct+tag`.
func (k *MFAKEK) Seal(plaintext []byte, aad []byte) ([]byte, error) {
	if k == nil || k.buf == nil {
		return nil, errors.New("mfa kek: not initialised")
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("mfa kek: nonce: %w", err)
	}
	return crypto.AESGCMSeal(k.buf.Bytes(), nonce, plaintext, aad)
}

// Open inverts Seal. AAD must match what was passed in at seal time.
func (k *MFAKEK) Open(blob []byte, aad []byte) ([]byte, error) {
	if k == nil || k.buf == nil {
		return nil, errors.New("mfa kek: not initialised")
	}
	return crypto.AESGCMOpen(k.buf.Bytes(), blob, aad)
}

// Close wipes the KEK from memory. Safe to call multiple times.
func (k *MFAKEK) Close() {
	if k == nil || k.buf == nil {
		return
	}
	k.buf.Destroy()
	k.buf = nil
}

// DecodeKEKSeed parses a hex or base64-encoded seed (env-supplied). Returns
// an empty slice (and no error) when input is empty; the caller handles the
// "no seed → per-instance random" path.
func DecodeKEKSeed(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	if b, err := hex.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, errors.New("mfa kek seed: not valid hex or base64")
}

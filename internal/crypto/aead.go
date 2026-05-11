// Package crypto contains the minimal server-side cryptographic primitives
// the oblivio backend needs. The bulk of crypto in this project runs in the
// browser (see frontend/packages/crypto); the server only ever touches keys
// that it owns itself — JWT signing material, K_login_totp derived from a
// freshly-supplied auth_key, etc. The server NEVER handles master_key,
// vault_key or item_key.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

const (
	nonceSize   = 12
	tagSize     = 16
	versionSize = 1

	// EnvelopeVersionV1 is the only currently-recognised crypto envelope
	// version. Layout: version(1) || nonce(12) || ciphertext+tag.
	// Future revisions (XChaCha20, post-quantum) bump this byte and add a
	// decoder branch — pre-v1 envelopes do not exist on disk anywhere.
	EnvelopeVersionV1 byte = 0x01
)

// AESGCMOpen decrypts an AES-256-GCM envelope of the form
// `version(1) || nonce(12) || ciphertext+tag`. Unknown versions are rejected.
// `aad` is the additional-authenticated-data agreed with the client.
func AESGCMOpen(key, blob []byte, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("aead: key length %d, want 32", len(key))
	}
	if len(blob) < versionSize+nonceSize+tagSize {
		return nil, errors.New("aead: blob too short")
	}
	if blob[0] != EnvelopeVersionV1 {
		return nil, fmt.Errorf("aead: unsupported envelope version 0x%02x", blob[0])
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aead: new cipher: %w", err)
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, fmt.Errorf("aead: new gcm: %w", err)
	}
	nonce := blob[versionSize : versionSize+nonceSize]
	ct := blob[versionSize+nonceSize:]
	pt, err := g.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("aead: open: %w", err)
	}
	return pt, nil
}

// AESGCMSeal returns `version(1) || nonce(12) || ct+tag`. The nonce must be 12
// random bytes from the caller and MUST NOT repeat for the same key. This
// helper is only used by tests today; production traffic does not encrypt on
// the server.
func AESGCMSeal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("aead: key length %d, want 32", len(key))
	}
	if len(nonce) != nonceSize {
		return nil, fmt.Errorf("aead: nonce length %d, want %d", len(nonce), nonceSize)
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aead: new cipher: %w", err)
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, fmt.Errorf("aead: new gcm: %w", err)
	}
	ct := g.Seal(nil, nonce, plaintext, aad)
	out := make([]byte, 0, versionSize+nonceSize+len(ct))
	out = append(out, EnvelopeVersionV1)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// HKDF-SHA256 derive key of length outLen using info label
func HKDFSHA256(ikm []byte, info string, outLen int) ([]byte, error) {
	r := hkdf.New(sha256.New, ikm, nil, []byte(info))
	out := make([]byte, outLen)
	if _, err := r.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}

// HMACSHA256 computes HMAC-SHA256(key, data...)
func HMACSHA256(key []byte, data ...[]byte) [32]byte {
	mac := hmac.New(sha256.New, key)
	for _, d := range data {
		mac.Write(d)
	}
	var out [32]byte
	sum := mac.Sum(nil)
	copy(out[:], sum)
	return out
}

// AEAD provides XChaCha20-Poly1305 sealing/opening
type AEAD struct {
	aead cipherAead
}

type cipherAead interface {
	NonceSize() int
	Overhead() int
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

func NewXChaCha20Poly1305(key []byte) (*AEAD, error) {
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return &AEAD{aead: a}, nil
}

func (a *AEAD) NonceSize() int { return a.aead.NonceSize() }
func (a *AEAD) Overhead() int  { return a.aead.Overhead() }

func (a *AEAD) Seal(nonce, plaintext, aad []byte) ([]byte, error) {
	if len(nonce) != a.aead.NonceSize() {
		return nil, fmt.Errorf("bad nonce length: %d", len(nonce))
	}
	out := a.aead.Seal(nil, nonce, plaintext, aad)
	return out, nil
}

func (a *AEAD) Open(nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(nonce) != a.aead.NonceSize() {
		return nil, fmt.Errorf("bad nonce length: %d", len(nonce))
	}
	pt, err := a.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, err
	}
	return pt, nil
}

// Helpers to build AAD
func BuildItemAAD(vaultID, itemID string, version uint32) []byte {
	// AAD: vault_id | item_id | version | "item" | v=1
	ver := make([]byte, 4)
	binary.BigEndian.PutUint32(ver, version)
	aad := make([]byte, 0, len(vaultID)+len(itemID)+4+5+1)
	aad = append(aad, []byte(vaultID)...)
	aad = append(aad, []byte(itemID)...)
	aad = append(aad, ver...)
	aad = append(aad, []byte("item")...)
	aad = append(aad, 1)
	return aad
}

var ErrMACMismatch = errors.New("mac mismatch")

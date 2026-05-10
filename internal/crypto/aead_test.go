package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestAESGCMRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce)

	plaintext := []byte("oblivio test secret")
	aad := []byte("oblivio/login-totp/v1")

	sealed, err := AESGCMSeal(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if len(sealed) != len(nonce)+len(plaintext)+16 {
		t.Fatalf("sealed length %d, want %d", len(sealed), len(nonce)+len(plaintext)+16)
	}
	pt, err := AESGCMOpen(key, sealed, aad)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestAESGCMRejectsTampering(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce)
	sealed, _ := AESGCMSeal(key, nonce, []byte("hi"), []byte("aad"))

	// flip a bit in the ciphertext part.
	sealed[len(sealed)-1] ^= 1
	if _, err := AESGCMOpen(key, sealed, []byte("aad")); err == nil {
		t.Fatal("expected open to reject tampered ciphertext")
	}
}

func TestAESGCMRejectsAADMismatch(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce)
	sealed, _ := AESGCMSeal(key, nonce, []byte("hi"), []byte("good-aad"))
	if _, err := AESGCMOpen(key, sealed, []byte("bad-aad")); err == nil {
		t.Fatal("expected open to reject AAD mismatch")
	}
}

func TestAESGCMRejectsShortBlob(t *testing.T) {
	key := make([]byte, 32)
	if _, err := AESGCMOpen(key, []byte("short"), nil); err == nil {
		t.Fatal("expected error for short blob")
	}
}

func TestAESGCMRejectsBadKeyLength(t *testing.T) {
	if _, err := AESGCMOpen(make([]byte, 16), make([]byte, 28), nil); err == nil {
		t.Fatal("expected error for 16-byte key")
	}
}

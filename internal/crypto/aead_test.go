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
	wantLen := 1 + len(nonce) + len(plaintext) + 16
	if len(sealed) != wantLen {
		t.Fatalf("sealed length %d, want %d", len(sealed), wantLen)
	}
	if sealed[0] != EnvelopeVersionV1 {
		t.Fatalf("sealed[0] = 0x%02x, want 0x%02x", sealed[0], EnvelopeVersionV1)
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
	if _, err := AESGCMOpen(make([]byte, 16), make([]byte, 29), nil); err == nil {
		t.Fatal("expected error for 16-byte key")
	}
}

func TestAESGCMRejectsUnknownVersion(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce)
	sealed, _ := AESGCMSeal(key, nonce, []byte("payload"), []byte("aad"))

	// Replace the version byte with something unknown; decryption should
	// fail before AES-GCM is even attempted.
	sealed[0] = 0x02
	if _, err := AESGCMOpen(key, sealed, []byte("aad")); err == nil {
		t.Fatal("expected open to reject unknown envelope version")
	}
}

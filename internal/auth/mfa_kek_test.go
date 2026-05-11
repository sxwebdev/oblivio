package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestNewMFAKEK_RandomFallback(t *testing.T) {
	k, err := NewMFAKEK(nil)
	if err != nil {
		t.Fatalf("nil seed: %v", err)
	}
	defer k.Close()
	if !k.IsInstanceLocal() {
		t.Error("nil seed must produce instance-local KEK")
	}
}

func TestNewMFAKEK_SharedSeedDeterministic(t *testing.T) {
	seed := bytes.Repeat([]byte{0xab}, 32)
	k1, err := NewMFAKEK(seed)
	if err != nil {
		t.Fatalf("k1: %v", err)
	}
	defer k1.Close()
	k2, err := NewMFAKEK(seed)
	if err != nil {
		t.Fatalf("k2: %v", err)
	}
	defer k2.Close()

	// Two KEKs from the same seed must seal identically for a given
	// (plaintext, nonce) pair — verified indirectly by sealing the same
	// payload twice and decrypting through the OTHER KEK.
	plaintext := []byte("oblivio-test-payload")
	aad := []byte("aad")
	blob, err := k1.Seal(plaintext, aad)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := k2.Open(blob, aad)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Error("plaintext mismatch — KEKs differ for identical seed")
	}
	if k1.IsInstanceLocal() || k2.IsInstanceLocal() {
		t.Error("shared-seed KEK reported as instance-local")
	}
}

func TestNewMFAKEK_ShortSeedRejected(t *testing.T) {
	if _, err := NewMFAKEK(bytes.Repeat([]byte{1}, 8)); err == nil {
		t.Fatal("expected error for 8-byte seed")
	}
}

func TestMFAKEKSealOpenAADMismatch(t *testing.T) {
	k, err := NewMFAKEK(nil)
	if err != nil {
		t.Fatalf("kek: %v", err)
	}
	defer k.Close()

	blob, err := k.Seal([]byte("payload"), []byte("aad-1"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := k.Open(blob, []byte("aad-2")); err == nil {
		t.Error("expected open to reject AAD mismatch")
	}
}

func TestMFAKEKCloseIdempotent(t *testing.T) {
	k, _ := NewMFAKEK(nil)
	k.Close()
	k.Close() // must not panic

	// After Close, Seal/Open must not panic — they return an error.
	if _, err := k.Seal([]byte("p"), nil); err == nil {
		t.Error("expected error sealing with destroyed KEK")
	}
}

func TestMFAKEKNilReceiver(t *testing.T) {
	var k *MFAKEK
	if !k.IsInstanceLocal() {
		t.Error("nil receiver should report instance-local")
	}
	if _, err := k.Seal(nil, nil); err == nil {
		t.Error("nil receiver Seal should error")
	}
	if _, err := k.Open(nil, nil); err == nil {
		t.Error("nil receiver Open should error")
	}
	k.Close() // must not panic
}

func TestDecodeKEKSeed_AllEncodings(t *testing.T) {
	raw := bytes.Repeat([]byte{0xa5}, 32)
	cases := []struct {
		name string
		in   string
	}{
		{"hex", hex.EncodeToString(raw)},
		{"std-base64", base64.StdEncoding.EncodeToString(raw)},
		{"raw-base64", base64.RawStdEncoding.EncodeToString(raw)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := DecodeKEKSeed(c.in)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !bytes.Equal(got, raw) {
				t.Errorf("decoded bytes mismatch")
			}
		})
	}
}

func TestDecodeKEKSeed_EmptyAndGarbage(t *testing.T) {
	if b, err := DecodeKEKSeed(""); err != nil || b != nil {
		t.Errorf("empty input should be (nil, nil); got (%v, %v)", b, err)
	}
	if _, err := DecodeKEKSeed("!@#$ not-valid-anything"); err == nil {
		t.Error("expected error for garbage seed")
	}
}

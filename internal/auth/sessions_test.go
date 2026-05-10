package auth

import (
	"crypto/sha256"
	"testing"
)

func TestTokenHash(t *testing.T) {
	got := TokenHash("token-abc")
	if len(got) != 32 {
		t.Fatalf("len=%d, want 32", len(got))
	}
	// Idempotent.
	if string(got) != string(TokenHash("token-abc")) {
		t.Fatal("hash is not deterministic")
	}
	// Different input → different hash.
	if string(got) == string(TokenHash("token-xyz")) {
		t.Fatal("distinct tokens hashed to the same digest")
	}
	// Matches the spec literally.
	want := sha256.Sum256([]byte("token-abc"))
	if string(got) != string(want[:]) {
		t.Fatal("hash deviates from SHA-256(token)")
	}
}

func TestTokenHash_Empty(t *testing.T) {
	got := TokenHash("")
	if len(got) != 32 {
		t.Fatal("empty input still must produce a 32-byte digest")
	}
}

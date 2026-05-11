package auth

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSecrets_VaultPassthrough(t *testing.T) {
	access := base64.RawStdEncoding.EncodeToString(randBytes(32))
	refresh := base64.RawStdEncoding.EncodeToString(randBytes(32))
	s, err := LoadSecrets("", access, refresh)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.AccessSecret() != access {
		t.Fatal("AccessSecret round-trip mismatch")
	}
	if s.RefreshSecret() != refresh {
		t.Fatal("RefreshSecret round-trip mismatch")
	}
}

func TestLoadSecrets_FilePersists(t *testing.T) {
	dir := t.TempDir()
	s, err := LoadSecrets(dir, "", "")
	if err != nil {
		t.Fatal(err)
	}
	got := s.AccessSecret() + "|" + s.RefreshSecret()
	s.Close()

	// File must be 0600.
	info, err := os.Stat(filepath.Join(dir, "secrets.json"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("secrets.json mode = %v, want 0600", mode)
	}

	// Re-loading returns the same material.
	s2, err := LoadSecrets(dir, "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if s2.AccessSecret()+"|"+s2.RefreshSecret() != got {
		t.Fatal("secrets.json was rewritten on reload")
	}
}

func TestSecretsCloseZeros(t *testing.T) {
	// After Close, AccessSecret/RefreshSecret must return empty (no panic).
	s, err := LoadSecrets("", "a", "b")
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if s.AccessSecret() != "" || s.RefreshSecret() != "" {
		t.Fatal("expected empty secrets after Close")
	}
	// Idempotent.
	s.Close()
}

func TestLoadSecrets_RejectIncompleteFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "secrets.json"), []byte(`{"access_token_secret":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSecrets(dir, "", ""); err == nil {
		t.Fatal("expected error for incomplete secrets.json")
	}
}

func TestLoadSecrets_RejectGarbageFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "secrets.json"), []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSecrets(dir, "", ""); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestSecretsNil(t *testing.T) {
	var s *Secrets
	if s.AccessSecret() != "" || s.RefreshSecret() != "" {
		t.Fatal("nil receiver should return empty strings")
	}
	s.Close() // must not panic
}

func TestLoadSecrets_MasterSeedDeterministic(t *testing.T) {
	// Same seed must derive identical access/refresh keys on every load —
	// otherwise a multi-instance deploy would reject each other's tokens.
	seed := base64.RawStdEncoding.EncodeToString(randBytes(48))
	t.Setenv("OBLIVIO_MASTER_SEED", seed)

	s1, err := LoadSecrets(t.TempDir(), "", "")
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	defer s1.Close()
	s2, err := LoadSecrets(t.TempDir(), "", "")
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	defer s2.Close()
	if s1.AccessSecret() != s2.AccessSecret() {
		t.Error("access secrets diverged for same seed")
	}
	if s1.RefreshSecret() != s2.RefreshSecret() {
		t.Error("refresh secrets diverged for same seed")
	}
	if s1.AccessSecret() == s1.RefreshSecret() {
		t.Error("access and refresh must be domain-separated")
	}
}

func TestLoadSecrets_MasterSeedShortFails(t *testing.T) {
	t.Setenv("OBLIVIO_MASTER_SEED", base64.RawStdEncoding.EncodeToString(randBytes(16)))
	if _, err := LoadSecrets(t.TempDir(), "", ""); err == nil {
		t.Fatal("expected rejection of <32-byte seed")
	}
}

func TestLoadSecrets_MasterSeedGarbageFails(t *testing.T) {
	t.Setenv("OBLIVIO_MASTER_SEED", "not-hex-not-base64-!@#$")
	if _, err := LoadSecrets(t.TempDir(), "", ""); err == nil {
		t.Fatal("expected rejection of malformed seed")
	}
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

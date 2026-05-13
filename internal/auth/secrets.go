package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/hkdf"
)

// Warnf matches the structured-logger Warnf method (e.g. mx/logger). Used
// by LoadSecrets so the on-disk fallback warning lands in the application
// log stream instead of bare stderr. Pass nil from tests/scripts.
type Warnf func(format string, args ...any)

// Secrets owns the signing keys for access and refresh tokens. Both keys are
// held inside memguard.LockedBuffer pages so they are excluded from core dumps
// and zeroed on Destroy. Call Close when the process shuts down.
type Secrets struct {
	access  *memguard.LockedBuffer
	refresh *memguard.LockedBuffer
}

// AccessSecret returns the access-token signing key as a string. The returned
// value is a copy; the underlying buffer remains locked.
func (s *Secrets) AccessSecret() string {
	if s == nil || s.access == nil {
		return ""
	}
	return string(s.access.Bytes())
}

// RefreshSecret returns the refresh-token signing key as a string.
func (s *Secrets) RefreshSecret() string {
	if s == nil || s.refresh == nil {
		return ""
	}
	return string(s.refresh.Bytes())
}

// Close wipes the locked buffers.
func (s *Secrets) Close() {
	if s == nil {
		return
	}
	if s.access != nil {
		s.access.Destroy()
		s.access = nil
	}
	if s.refresh != nil {
		s.refresh.Destroy()
		s.refresh = nil
	}
}

// LoadSecrets resolves access/refresh signing keys in this order:
//  1. Explicit `access` and `refresh` from config (typically Vault).
//  2. `OBLIVIO_MASTER_SEED` env var: a 32+ byte seed (hex or base64) that
//     gets fed through HKDF-SHA256 with two distinct info labels to derive
//     stable access/refresh keys. Same seed → same keys across restarts
//     and across multi-instance deploys, no on-disk state needed.
//  3. On-disk `dir/secrets.json` with mode 0o600 (self-hosted dev fallback).
//
// The HKDF path is the recommended production setup when Vault is not
// available: keep the seed in your secret manager (1Password, sealed env,
// etc.) and the binary never touches the disk for signing material.
func LoadSecrets(warn Warnf, dir, access, refresh string) (*Secrets, error) {
	if access != "" && refresh != "" {
		return wrapSecrets([]byte(access), []byte(refresh))
	}
	if seed := os.Getenv("OBLIVIO_MASTER_SEED"); seed != "" {
		raw, err := decodeMasterSeed(seed)
		if err != nil {
			return nil, fmt.Errorf("OBLIVIO_MASTER_SEED: %w", err)
		}
		if len(raw) < 32 {
			return nil, fmt.Errorf("OBLIVIO_MASTER_SEED: need ≥32 bytes, got %d", len(raw))
		}
		accessKey, err := deriveSeedKey(raw, "oblivio/jwt-access/v1")
		if err != nil {
			return nil, err
		}
		refreshKey, err := deriveSeedKey(raw, "oblivio/jwt-refresh/v1")
		if err != nil {
			return nil, err
		}
		// Encode as base64 so the downstream consumers (which treat the
		// signing secret as an opaque string) see the same shape they
		// get from the Vault/on-disk paths.
		return wrapSecrets(
			[]byte(base64.RawStdEncoding.EncodeToString(accessKey)),
			[]byte(base64.RawStdEncoding.EncodeToString(refreshKey)),
		)
	}

	if dir == "" {
		dir = "data/secrets"
	}
	path := filepath.Join(dir, "secrets.json")
	// Loud warning so operators notice the weakest configuration mode in
	// startup logs. The on-disk file holds the JWT signing material in
	// plaintext base64; protect the disk accordingly or move to Vault /
	// OBLIVIO_MASTER_SEED.
	if warn != nil {
		warn("auth.LoadSecrets: falling back to on-disk secrets.json — prefer Vault or OBLIVIO_MASTER_SEED in production")
	}

	type onDisk struct {
		Access  string `json:"access_token_secret"`
		Refresh string `json:"refresh_token_secret"`
	}

	if data, err := os.ReadFile(path); err == nil {
		var od onDisk
		if err := json.Unmarshal(data, &od); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		if od.Access == "" || od.Refresh == "" {
			return nil, fmt.Errorf("incomplete secrets file: %s", path)
		}
		return wrapSecrets([]byte(od.Access), []byte(od.Refresh))
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	// Generate fresh keys and persist with restrictive permissions.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}
	a, err := randomKey()
	if err != nil {
		return nil, err
	}
	r, err := randomKey()
	if err != nil {
		return nil, err
	}
	od := onDisk{Access: a, Refresh: r}
	buf, _ := json.Marshal(od)
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		return nil, fmt.Errorf("write %s: %w", path, err)
	}
	return wrapSecrets([]byte(a), []byte(r))
}

func wrapSecrets(access, refresh []byte) (*Secrets, error) {
	if len(access) == 0 || len(refresh) == 0 {
		return nil, fmt.Errorf("empty signing key")
	}
	// NewBufferFromBytes wipes the source slice after copying.
	return &Secrets{
		access:  memguard.NewBufferFromBytes(access),
		refresh: memguard.NewBufferFromBytes(refresh),
	}, nil
}

func randomKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random key: %w", err)
	}
	return base64.RawStdEncoding.EncodeToString(b), nil
}

// decodeMasterSeed accepts a hex, std-base64, or raw-base64 encoded seed
// and returns the decoded bytes. Returns an error only when none of the
// codecs accept the input — common typos like trailing whitespace are
// normalised away.
func decodeMasterSeed(s string) ([]byte, error) {
	if b, err := hex.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, fmt.Errorf("not valid hex or base64")
}

// deriveSeedKey runs HKDF-SHA256 over the master seed with the given info
// label and returns a 32-byte key. The info label is the domain
// separation — same seed + different label → independent keys.
func deriveSeedKey(seed []byte, info string) ([]byte, error) {
	r := hkdf.New(sha256.New, seed, nil, []byte(info))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("derive %s: %w", info, err)
	}
	return out, nil
}

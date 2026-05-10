package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/awnumar/memguard"
)

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
//  1. If `access` and `refresh` are non-empty (e.g. supplied by Vault), use them.
//  2. Otherwise read/write a JSON file under `dir/secrets.json` with mode 0600.
//
// The on-disk fallback is for self-hosted dev/single-node deployments where
// Vault is not configured. Keys are 32 random bytes, base64-encoded.
func LoadSecrets(dir, access, refresh string) (*Secrets, error) {
	if access != "" && refresh != "" {
		return wrapSecrets([]byte(access), []byte(refresh))
	}

	if dir == "" {
		dir = "data/secrets"
	}
	path := filepath.Join(dir, "secrets.json")

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

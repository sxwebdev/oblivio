package auth

import (
	"errors"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// MFAChallenge captures the partial-login state created after a successful
// password (auth_key) check when the user has 2FA enabled. The client must
// complete one factor (TOTP code OR WebAuthn assertion) within the TTL.
//
// The bound `AuthKey` is what allows us to derive K_login_totp without a
// re-roundtrip. It is kept in plain bytes (not memguard) because the store
// is in-memory and short-lived; if hardening is needed later this is the
// place to memguard it.
type MFAChallenge struct {
	ID            uuid.UUID
	UserID        uuid.UUID
	Email         string
	AuthKey       []byte // for re-deriving K_login_totp at completion
	DeviceID      string
	DeviceType    string
	DeviceName    string
	ExpiresAt     time.Time
	TOTPRequired  bool
	WebAuthnState *webauthn.SessionData
}

// Wipe zeroes the AuthKey slice so the secret-equivalent material doesn't
// linger on the heap once the challenge is consumed.
func (c *MFAChallenge) Wipe() {
	for i := range c.AuthKey {
		c.AuthKey[i] = 0
	}
	c.AuthKey = nil
}

// MFAStore holds short-lived challenges keyed by their UUID. It is a plain
// in-memory map — challenges expire after 5 minutes by default.
type MFAStore struct {
	mu      sync.Mutex
	items   map[uuid.UUID]MFAChallenge
	ttl     time.Duration
	stopGC  chan struct{}
	stopped bool
}

// NewMFAStore creates a store with the given TTL. The store starts a
// background GC goroutine that wakes up every TTL/2.
func NewMFAStore(ttl time.Duration) *MFAStore {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	s := &MFAStore{
		items:  make(map[uuid.UUID]MFAChallenge),
		ttl:    ttl,
		stopGC: make(chan struct{}),
	}
	go s.gcLoop()
	return s
}

// Put stores a challenge and returns its UUID. The TTL is set from the
// store's configured value.
func (s *MFAStore) Put(c MFAChallenge) uuid.UUID {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	c.ExpiresAt = time.Now().Add(s.ttl)
	s.items[c.ID] = c
	return c.ID
}

// Take removes and returns a challenge by id. Expired entries return
// ErrChallengeExpired.
//
// The caller is responsible for wiping the returned `AuthKey` slice as soon
// as it is no longer needed (see (*MFAChallenge).Wipe).
func (s *MFAStore) Take(id uuid.UUID) (MFAChallenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.items[id]
	if !ok {
		return MFAChallenge{}, ErrChallengeNotFound
	}
	// Clear the stored copy so a delete-after-leak window doesn't keep the
	// auth_key in memory; the returned value owns the bytes from here on.
	stored := s.items[id]
	stored.AuthKey = nil
	s.items[id] = stored
	delete(s.items, id)
	if time.Now().After(c.ExpiresAt) {
		c.Wipe()
		return MFAChallenge{}, ErrChallengeExpired
	}
	return c, nil
}

// Peek returns a challenge without consuming it. Useful for WebAuthn flows
// where Take happens only after the assertion verifies.
func (s *MFAStore) Peek(id uuid.UUID) (MFAChallenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.items[id]
	if !ok {
		return MFAChallenge{}, ErrChallengeNotFound
	}
	if time.Now().After(c.ExpiresAt) {
		delete(s.items, id)
		return MFAChallenge{}, ErrChallengeExpired
	}
	return c, nil
}

// Close stops the GC goroutine. Safe to call multiple times.
func (s *MFAStore) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return
	}
	s.stopped = true
	close(s.stopGC)
}

func (s *MFAStore) gcLoop() {
	t := time.NewTicker(s.ttl / 2)
	defer t.Stop()
	for {
		select {
		case <-s.stopGC:
			return
		case <-t.C:
			s.sweep()
		}
	}
}

func (s *MFAStore) sweep() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, c := range s.items {
		if now.After(c.ExpiresAt) {
			delete(s.items, id)
		}
	}
}

// Sentinel errors so callers can distinguish "expired" from "never existed".
var (
	ErrChallengeNotFound = errors.New("mfa: challenge not found")
	ErrChallengeExpired  = errors.New("mfa: challenge expired")
)

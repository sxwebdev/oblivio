package auth

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// RecoverySession captures a successfully-proven recovery attempt. Holding it
// authorises the bearer to rotate their auth artefacts within the TTL.
type RecoverySession struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	Email     string
	ExpiresAt time.Time
}

// RecoveryStore is the in-memory companion to the RecoveryStart →
// RecoveryComplete handshake. A successful proof creates a session; the
// subsequent Complete call consumes it. Sessions expire after the configured
// TTL (15 minutes is the default — long enough for the user to pick a new
// password, short enough that a stolen recovery_code becomes useless quickly).
type RecoveryStore struct {
	mu      sync.Mutex
	items   map[uuid.UUID]RecoverySession
	ttl     time.Duration
	stopGC  chan struct{}
	stopped bool
}

// NewRecoveryStore returns a store backed by a plain map plus a GC goroutine.
func NewRecoveryStore(ttl time.Duration) *RecoveryStore {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	s := &RecoveryStore{
		items:  make(map[uuid.UUID]RecoverySession),
		ttl:    ttl,
		stopGC: make(chan struct{}),
	}
	go s.gcLoop()
	return s
}

// Put writes a session and returns its UUID.
func (s *RecoveryStore) Put(sess RecoverySession) uuid.UUID {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.ID == uuid.Nil {
		sess.ID = uuid.New()
	}
	sess.ExpiresAt = time.Now().Add(s.ttl)
	s.items[sess.ID] = sess
	return sess.ID
}

// Take removes and returns a session, surfacing whether it had expired.
func (s *RecoveryStore) Take(id uuid.UUID) (RecoverySession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.items[id]
	if !ok {
		return RecoverySession{}, ErrChallengeNotFound
	}
	delete(s.items, id)
	if time.Now().After(sess.ExpiresAt) {
		return RecoverySession{}, ErrChallengeExpired
	}
	return sess, nil
}

// Close stops the GC goroutine.
func (s *RecoveryStore) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return
	}
	s.stopped = true
	close(s.stopGC)
}

func (s *RecoveryStore) gcLoop() {
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

func (s *RecoveryStore) sweep() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.items {
		if now.After(sess.ExpiresAt) {
			delete(s.items, id)
		}
	}
}

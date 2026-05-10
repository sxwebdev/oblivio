package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRecoveryStore_PutTake(t *testing.T) {
	s := NewRecoveryStore(50 * time.Millisecond)
	defer s.Close()

	uid := uuid.New()
	id := s.Put(RecoverySession{UserID: uid, Email: "a@example.com"})
	if id == uuid.Nil {
		t.Fatal("Put returned zero UUID")
	}

	sess, err := s.Take(id)
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if sess.UserID != uid {
		t.Fatalf("UserID mismatch")
	}
	// Take is single-shot — second call must fail.
	if _, err := s.Take(id); err == nil {
		t.Fatal("expected error for second Take")
	}
}

func TestRecoveryStore_Expires(t *testing.T) {
	s := NewRecoveryStore(20 * time.Millisecond)
	defer s.Close()

	id := s.Put(RecoverySession{UserID: uuid.New()})
	time.Sleep(40 * time.Millisecond)
	if _, err := s.Take(id); err == nil {
		t.Fatal("expected expiry error")
	}
}

func TestRecoveryStore_GCSweep(t *testing.T) {
	s := NewRecoveryStore(20 * time.Millisecond)
	defer s.Close()
	s.Put(RecoverySession{UserID: uuid.New()})
	// Let two GC ticks run; map should be empty by then.
	time.Sleep(60 * time.Millisecond)
	s.mu.Lock()
	n := len(s.items)
	s.mu.Unlock()
	if n != 0 {
		t.Fatalf("expected GC to empty map, got %d", n)
	}
}

func TestRecoveryStore_CloseIdempotent(t *testing.T) {
	s := NewRecoveryStore(time.Second)
	s.Close()
	s.Close() // must not panic
}

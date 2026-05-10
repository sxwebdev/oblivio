package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMFAStorePutTakeRoundTrip(t *testing.T) {
	s := NewMFAStore(time.Minute)
	defer s.Close()

	userID := uuid.New()
	id := s.Put(MFAChallenge{UserID: userID, Email: "a@b", TOTPRequired: true})

	got, err := s.Take(id)
	if err != nil {
		t.Fatalf("take: %v", err)
	}
	if got.UserID != userID || !got.TOTPRequired {
		t.Errorf("unexpected challenge: %+v", got)
	}
	// Second take should be NotFound (consumed).
	if _, err := s.Take(id); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("second take: %v, want ErrChallengeNotFound", err)
	}
}

func TestMFAStorePeekDoesNotConsume(t *testing.T) {
	s := NewMFAStore(time.Minute)
	defer s.Close()

	id := s.Put(MFAChallenge{UserID: uuid.New()})
	for i := range 3 {
		if _, err := s.Peek(id); err != nil {
			t.Errorf("peek %d: %v", i, err)
		}
	}
	if _, err := s.Take(id); err != nil {
		t.Errorf("final take: %v", err)
	}
}

func TestMFAStoreExpiry(t *testing.T) {
	s := NewMFAStore(50 * time.Millisecond)
	defer s.Close()

	id := s.Put(MFAChallenge{UserID: uuid.New()})
	time.Sleep(80 * time.Millisecond)
	// After TTL we expect the challenge to be unusable. Whether it surfaces
	// as Expired or NotFound depends on a race with the GC sweep — both are
	// "you must start over" from the client's perspective.
	_, err := s.Take(id)
	if !errors.Is(err, ErrChallengeExpired) && !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("take after TTL: %v, want Expired or NotFound", err)
	}
}

func TestRecoveryStoreRoundTrip(t *testing.T) {
	s := NewRecoveryStore(time.Minute)
	defer s.Close()

	userID := uuid.New()
	id := s.Put(RecoverySession{UserID: userID, Email: "a@b"})
	got, err := s.Take(id)
	if err != nil {
		t.Fatalf("take: %v", err)
	}
	if got.UserID != userID {
		t.Errorf("user id mismatch")
	}
	if _, err := s.Take(id); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("second take: %v, want ErrChallengeNotFound", err)
	}
}

func TestRecoveryStoreExpiry(t *testing.T) {
	s := NewRecoveryStore(50 * time.Millisecond)
	defer s.Close()

	id := s.Put(RecoverySession{UserID: uuid.New()})
	time.Sleep(80 * time.Millisecond)
	_, err := s.Take(id)
	if !errors.Is(err, ErrChallengeExpired) && !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("take after TTL: %v, want Expired or NotFound", err)
	}
}

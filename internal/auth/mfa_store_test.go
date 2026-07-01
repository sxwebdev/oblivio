package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sxwebdev/oblivio/internal/store/repos/repo_mfa_challenges"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_recovery_sessions"
	"github.com/sxwebdev/oblivio/internal/testutil"
)

// newTestMFAStore boots a fresh Postgres, seeds a user row (FK requirement),
// and returns the store plus the seeded UUID.
func newTestMFAStore(t *testing.T, ttl time.Duration) (*MFAStore, *pgxpool.Pool, uuid.UUID) {
	t.Helper()
	testutil.SkipIfNoDocker(t)
	pg := testutil.NewPostgres(t)
	uidStr := pg.SeedUser(context.Background(), t, "mfa-test@example.com")
	uid, err := uuid.Parse(uidStr)
	if err != nil {
		t.Fatalf("parse uid: %v", err)
	}
	repo := repo_mfa_challenges.New(pg.Pool)
	kek, err := NewMFAKEK(nil)
	if err != nil {
		t.Fatalf("kek: %v", err)
	}
	t.Cleanup(kek.Close)
	s, err := NewMFAStore(repo, kek, ttl)
	if err != nil {
		t.Fatalf("mfa store: %v", err)
	}
	t.Cleanup(s.Close)
	return s, pg.Pool, uid
}

func newTestRecoveryStore(t *testing.T, ttl time.Duration) (*RecoveryStore, *pgxpool.Pool, uuid.UUID) {
	t.Helper()
	testutil.SkipIfNoDocker(t)
	pg := testutil.NewPostgres(t)
	uidStr := pg.SeedUser(context.Background(), t, "recovery-test@example.com")
	uid, err := uuid.Parse(uidStr)
	if err != nil {
		t.Fatalf("parse uid: %v", err)
	}
	repo := repo_recovery_sessions.New(pg.Pool)
	s, err := NewRecoveryStore(repo, ttl)
	if err != nil {
		t.Fatalf("recovery store: %v", err)
	}
	t.Cleanup(s.Close)
	return s, pg.Pool, uid
}

func randomAuthKey(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("random: %v", err)
	}
	return b
}

func TestMFAStorePutTakeRoundTrip(t *testing.T) {
	s, _, uid := newTestMFAStore(t, time.Minute)
	ctx := context.Background()

	authKey := randomAuthKey(t)
	id, err := s.Put(ctx, MFAChallenge{
		UserID:       uid,
		Email:        "mfa-test@example.com",
		AuthKey:      authKey,
		TOTPRequired: true,
	})
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := s.Take(ctx, id)
	if err != nil {
		t.Fatalf("take: %v", err)
	}
	if got.UserID != uid || !got.TOTPRequired {
		t.Errorf("unexpected challenge: %+v", got)
	}
	// Auth key round-trips byte-for-byte through KEK seal/open.
	if string(got.AuthKey) != string(authKey) {
		t.Errorf("auth_key round-trip mismatch")
	}
	if _, err := s.Take(ctx, id); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("second take: %v, want ErrChallengeNotFound", err)
	}
}

// TestMFAStorePutWithoutAuthKey covers the WebAuthn registration path,
// where the ceremony runs for an already-authenticated user and the
// challenge has no auth_key to encrypt. Regression test for the
// NOT NULL constraint on mfa_challenges.auth_key_ct (migration 011).
func TestMFAStorePutWithoutAuthKey(t *testing.T) {
	s, _, uid := newTestMFAStore(t, time.Minute)
	ctx := context.Background()

	id, err := s.Put(ctx, MFAChallenge{
		UserID:     uid,
		Email:      "mfa-test@example.com",
		DeviceName: "macbook",
	})
	if err != nil {
		t.Fatalf("put without auth_key: %v", err)
	}
	got, err := s.Take(ctx, id)
	if err != nil {
		t.Fatalf("take: %v", err)
	}
	if got.AuthKey != nil {
		t.Errorf("AuthKey = %v, want nil for WebAuthn-registration challenge", got.AuthKey)
	}
	if got.DeviceName != "macbook" {
		t.Errorf("DeviceName = %q, want %q", got.DeviceName, "macbook")
	}
}

func TestMFAStorePeekDoesNotConsume(t *testing.T) {
	s, _, uid := newTestMFAStore(t, time.Minute)
	ctx := context.Background()

	id, err := s.Put(ctx, MFAChallenge{
		UserID:  uid,
		Email:   "mfa-test@example.com",
		AuthKey: randomAuthKey(t),
	})
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	for i := range 3 {
		if _, err := s.Peek(ctx, id); err != nil {
			t.Errorf("peek %d: %v", i, err)
		}
	}
	if _, err := s.Take(ctx, id); err != nil {
		t.Errorf("final take: %v", err)
	}
}

// TestMFAStoreFailedAttemptsBurnsChallenge documents the C-1 fix:
// RecordFailedAttempt increments the per-challenge counter and burns
// the row once it hits MaxMFAFailedAttempts so an attacker who has
// the user's password cannot brute-force TOTP/WebAuthn codes within
// the 5-minute challenge window.
func TestMFAStoreFailedAttemptsBurnsChallenge(t *testing.T) {
	s, _, uid := newTestMFAStore(t, time.Minute)
	ctx := context.Background()

	id, err := s.Put(ctx, MFAChallenge{
		UserID:       uid,
		Email:        "mfa-test@example.com",
		AuthKey:      randomAuthKey(t),
		TOTPRequired: true,
	})
	if err != nil {
		t.Fatalf("put: %v", err)
	}

	// First MaxMFAFailedAttempts-1 attempts increment without burning.
	for i := 1; i < MaxMFAFailedAttempts; i++ {
		if err := s.RecordFailedAttempt(ctx, id); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}

	// The threshold attempt burns the row.
	if err := s.RecordFailedAttempt(ctx, id); !errors.Is(err, ErrChallengeBurned) {
		t.Fatalf("threshold attempt: %v, want ErrChallengeBurned", err)
	}

	// After burning, Peek/Take must report NotFound.
	if _, err := s.Peek(ctx, id); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("peek after burn: %v, want ErrChallengeNotFound", err)
	}

	// Further increments on a burned row also surface NotFound.
	if err := s.RecordFailedAttempt(ctx, id); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("increment after burn: %v, want ErrChallengeNotFound", err)
	}
}

func TestMFAStoreExpiry(t *testing.T) {
	s, _, uid := newTestMFAStore(t, 50*time.Millisecond)
	ctx := context.Background()

	id, err := s.Put(ctx, MFAChallenge{
		UserID:  uid,
		Email:   "mfa-test@example.com",
		AuthKey: randomAuthKey(t),
	})
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	time.Sleep(80 * time.Millisecond)
	_, err = s.Take(ctx, id)
	if !errors.Is(err, ErrChallengeExpired) && !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("take after TTL: %v, want Expired or NotFound", err)
	}
}

func TestRecoveryStoreRoundTrip(t *testing.T) {
	s, _, uid := newTestRecoveryStore(t, time.Minute)
	ctx := context.Background()

	id, err := s.Put(ctx, RecoverySession{UserID: uid, Email: "recovery-test@example.com"})
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := s.Take(ctx, id)
	if err != nil {
		t.Fatalf("take: %v", err)
	}
	if got.UserID != uid {
		t.Errorf("user id mismatch")
	}
	if _, err := s.Take(ctx, id); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("second take: %v, want ErrChallengeNotFound", err)
	}
}

func TestRecoveryStoreExpiry(t *testing.T) {
	s, _, uid := newTestRecoveryStore(t, 50*time.Millisecond)
	ctx := context.Background()

	id, err := s.Put(ctx, RecoverySession{UserID: uid})
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	time.Sleep(80 * time.Millisecond)
	_, err = s.Take(ctx, id)
	if !errors.Is(err, ErrChallengeExpired) && !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("take after TTL: %v, want Expired or NotFound", err)
	}
}

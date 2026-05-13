package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/sxwebdev/oblivio/internal/store/repos/repo_recovery_sessions"
)

// RecoverySession captures a successfully-proven recovery attempt. Holding it
// authorises the bearer to rotate their auth artefacts within the TTL.
type RecoverySession struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	Email     string
	ExpiresAt time.Time
}

// RecoveryStore is the Postgres-backed companion to the RecoveryStart →
// RecoveryComplete handshake. A successful proof creates a session row; the
// subsequent Complete call atomically deletes-and-returns it. Sessions
// expire after the configured TTL (15 minutes is the default).
//
// Unlike MFAChallenge, recovery sessions hold no secret material — the row
// is a capability token and nothing more, so no KEK is needed.
type RecoveryStore struct {
	repo *repo_recovery_sessions.Queries
	ttl  time.Duration
}

// NewRecoveryStore returns a store backed by the given repository.
func NewRecoveryStore(repo *repo_recovery_sessions.Queries, ttl time.Duration) (*RecoveryStore, error) {
	if repo == nil {
		return nil, errors.New("recovery store: repo required")
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &RecoveryStore{repo: repo, ttl: ttl}, nil
}

// Put writes a session row and returns its UUID. Caller-supplied IDs are
// honoured for testability; otherwise a fresh UUIDv4 is generated.
func (s *RecoveryStore) Put(ctx context.Context, sess RecoverySession) (uuid.UUID, error) {
	if sess.ID == uuid.Nil {
		sess.ID = uuid.New()
	}
	sess.ExpiresAt = time.Now().Add(s.ttl)
	_, err := s.repo.InsertRecoverySession(ctx, repo_recovery_sessions.InsertRecoverySessionParams{
		ID:        sess.ID,
		UserID:    sess.UserID,
		Email:     sess.Email,
		ExpiresAt: pgtype.Timestamptz{Time: sess.ExpiresAt, Valid: true},
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("recovery store: insert: %w", err)
	}
	return sess.ID, nil
}

// Take atomically deletes and returns a session, surfacing whether it had
// expired. Concurrent Take calls race-safely: the SQL DELETE...RETURNING
// guarantees only one caller observes the row.
func (s *RecoveryStore) Take(ctx context.Context, id uuid.UUID) (RecoverySession, error) {
	row, err := s.repo.TakeRecoverySession(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return RecoverySession{}, ErrChallengeNotFound
		}
		return RecoverySession{}, fmt.Errorf("recovery store: take: %w", err)
	}
	sess := RecoverySession{
		ID:        row.ID,
		UserID:    row.UserID,
		Email:     row.Email,
		ExpiresAt: row.ExpiresAt.Time,
	}
	if time.Now().After(sess.ExpiresAt) {
		return RecoverySession{}, ErrChallengeExpired
	}
	return sess, nil
}

// Close is a no-op for the Postgres-backed store. Kept for API parity.
func (s *RecoveryStore) Close() {}

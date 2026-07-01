package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/sxwebdev/oblivio/internal/models"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_mfa_challenges"
)

// MFAChallenge captures the partial-login state created after a successful
// password (auth_key) check when the user has 2FA enabled. The client must
// complete one factor (TOTP code OR WebAuthn assertion) within the TTL.
//
// AuthKey is what allows the server to derive K_login_totp at completion.
// At rest in Postgres it is encrypted under MFAKEK; in memory after a
// successful Take/Peek it lives in a plain slice that the caller MUST
// `Wipe()` once verification finishes.
type MFAChallenge struct {
	ID            uuid.UUID
	UserID        uuid.UUID
	Email         string
	AuthKey       []byte
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

// MFAStore is the Postgres-backed challenge store. Concurrent access is safe
// — `TakeMFAChallenge` is an atomic DELETE RETURNING, so two callers cannot
// both claim the same row.
//
// AuthKey bytes are at-rest-encrypted under MFAKEK. The KEK lives only in
// process memory (memguard); a DB dump alone is therefore insufficient to
// recover auth_key. WebAuthn SessionData is JSON-encoded — go-webauthn
// supports stdlib encoding/json round-trip on this type.
type MFAStore struct {
	repo *repo_mfa_challenges.Queries
	kek  *MFAKEK
	ttl  time.Duration
}

// NewMFAStore returns a Postgres-backed store. `ttl` defaults to 5 minutes.
// The KEK must be non-nil; pass an instance built by NewMFAKEK.
func NewMFAStore(repo *repo_mfa_challenges.Queries, kek *MFAKEK, ttl time.Duration) (*MFAStore, error) {
	if repo == nil {
		return nil, errors.New("mfa store: repo required")
	}
	if kek == nil {
		return nil, errors.New("mfa store: kek required")
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &MFAStore{repo: repo, kek: kek, ttl: ttl}, nil
}

// Put writes a challenge, returning its UUID. The caller's `c.AuthKey` is
// encrypted under the KEK; the original slice is not wiped by this method
// — callers that want zeroisation must do it themselves.
func (s *MFAStore) Put(ctx context.Context, c MFAChallenge) (uuid.UUID, error) {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	c.ExpiresAt = time.Now().Add(s.ttl)

	// WebAuthn registration challenges carry no auth_key — only the login
	// path does. An empty AuthKey is stored as NULL ciphertext and the
	// caller receives nil bytes back from Take/Peek.
	var ct []byte
	if len(c.AuthKey) > 0 {
		sealed, err := s.kek.Seal(c.AuthKey, kekAAD(c.ID))
		if err != nil {
			return uuid.Nil, fmt.Errorf("mfa store: seal auth_key: %w", err)
		}
		ct = sealed
	}

	var waJSON []byte
	if c.WebAuthnState != nil {
		j, err := json.Marshal(c.WebAuthnState)
		if err != nil {
			return uuid.Nil, fmt.Errorf("mfa store: marshal webauthn state: %w", err)
		}
		waJSON = j
	}

	_, err := s.repo.InsertMFAChallenge(ctx, repo_mfa_challenges.InsertMFAChallengeParams{
		ID:            c.ID,
		UserID:        c.UserID,
		Email:         c.Email,
		AuthKeyCt:     ct,
		DeviceID:      c.DeviceID,
		DeviceType:    c.DeviceType,
		DeviceName:    c.DeviceName,
		TotpRequired:  c.TOTPRequired,
		WebauthnState: waJSON,
		ExpiresAt:     pgtype.Timestamptz{Time: c.ExpiresAt, Valid: true},
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("mfa store: insert: %w", err)
	}
	return c.ID, nil
}

// MaxMFAFailedAttempts is the per-challenge ceiling. After this many
// failed TOTP/WebAuthn validations the challenge is burned and the
// caller must start a new sign-in flow.
const MaxMFAFailedAttempts = 5

// RecordFailedAttempt bumps the per-challenge counter and, if the
// threshold is hit, deletes the row and returns ErrChallengeBurned.
// Callers should treat ErrChallengeBurned and ErrChallengeNotFound as
// equivalent at the wire — both mean "this challenge is unusable now".
func (s *MFAStore) RecordFailedAttempt(ctx context.Context, id uuid.UUID) error {
	count, err := s.repo.IncrementMFAFailedAttempts(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrChallengeNotFound
		}
		return fmt.Errorf("mfa store: increment failed attempts: %w", err)
	}
	if count >= MaxMFAFailedAttempts {
		// Burn the challenge. Best-effort: a concurrent Take may have
		// already removed the row, in which case the delete is a no-op.
		_, _ = s.repo.DeleteMFAChallenge(ctx, id)
		return ErrChallengeBurned
	}
	return nil
}

// Take atomically deletes and returns the challenge. Expired rows return
// ErrChallengeExpired (after the row has already been removed — expired
// challenges are not retried). Concurrent Take calls are race-safe: only
// one caller observes the row.
func (s *MFAStore) Take(ctx context.Context, id uuid.UUID) (MFAChallenge, error) {
	row, err := s.repo.TakeMFAChallenge(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return MFAChallenge{}, ErrChallengeNotFound
		}
		return MFAChallenge{}, fmt.Errorf("mfa store: take: %w", err)
	}
	return s.materialise(row, true)
}

// Peek loads a challenge without consuming it. WebAuthn flows call Peek
// during BeginAssertion and only call Take once the assertion verifies.
func (s *MFAStore) Peek(ctx context.Context, id uuid.UUID) (MFAChallenge, error) {
	row, err := s.repo.GetMFAChallenge(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return MFAChallenge{}, ErrChallengeNotFound
		}
		return MFAChallenge{}, fmt.Errorf("mfa store: peek: %w", err)
	}
	return s.materialise(row, false)
}

// Close is a no-op for the Postgres-backed store. Kept for API parity with
// the previous in-memory implementation so callers don't need conditionals.
func (s *MFAStore) Close() {}

// materialise decrypts AuthKey, deserialises WebAuthnState, and reports
// ErrChallengeExpired when the row is past its deadline.
//
// `consumed` indicates whether the caller already removed the row. When
// peeking an expired row we delete it ourselves so the next Peek sees
// not-found; when Take returned an expired row the deletion already
// happened in SQL.
func (s *MFAStore) materialise(row *models.MfaChallenge, consumed bool) (MFAChallenge, error) {
	// WebAuthn registration challenges carry no auth_key — accept nil
	// ciphertext and return a nil AuthKey to the caller.
	var pt []byte
	if len(row.AuthKeyCt) > 0 {
		opened, err := s.kek.Open(row.AuthKeyCt, kekAAD(row.ID))
		if err != nil {
			return MFAChallenge{}, fmt.Errorf("mfa store: open auth_key: %w", err)
		}
		pt = opened
	}
	var wa *webauthn.SessionData
	if len(row.WebauthnState) > 0 {
		wa = &webauthn.SessionData{}
		if err := json.Unmarshal(row.WebauthnState, wa); err != nil {
			return MFAChallenge{}, fmt.Errorf("mfa store: unmarshal webauthn state: %w", err)
		}
	}
	c := MFAChallenge{
		ID:            row.ID,
		UserID:        row.UserID,
		Email:         row.Email,
		AuthKey:       pt,
		DeviceID:      row.DeviceID,
		DeviceType:    row.DeviceType,
		DeviceName:    row.DeviceName,
		TOTPRequired:  row.TotpRequired,
		WebAuthnState: wa,
		ExpiresAt:     row.ExpiresAt.Time,
	}
	if time.Now().After(c.ExpiresAt) {
		if !consumed {
			// Best-effort cleanup; ignore errors because the row is already
			// expired and the next sweep would catch it anyway.
			_, _ = s.repo.DeleteMFAChallenge(context.Background(), row.ID)
		}
		c.Wipe()
		return MFAChallenge{}, ErrChallengeExpired
	}
	return c, nil
}

// kekAAD binds the encrypted auth_key to its challenge id so an attacker
// cannot relocate a ciphertext from one row to another in the DB.
func kekAAD(id uuid.UUID) []byte {
	return []byte("oblivio/mfa-challenge/" + id.String())
}

// Sentinel errors so callers can distinguish "expired" from "never existed".
var (
	ErrChallengeNotFound = errors.New("mfa: challenge not found")
	ErrChallengeExpired  = errors.New("mfa: challenge expired")
	// ErrChallengeBurned signals that the per-challenge failed-attempt
	// counter exceeded MaxMFAFailedAttempts and the row was deleted.
	ErrChallengeBurned = errors.New("mfa: challenge burned after too many failed attempts")
)

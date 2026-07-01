// PG-backed implementation of tokenmanager.ITokenStore.
//
// The original codebase used tokenmanager.MemoryTokenStore, which makes
// revocation strictly process-local: TerminateSession only flipped a DB row
// that no code path actually consulted, and Logout could not invalidate the
// refresh token. Persisting tokens in Postgres lets ValidateToken do the
// cheap GetAuthToken lookup once per request and turns RevokeToken into an
// authoritative action that survives across replicas and restarts.
//
// `value` is the verbatim tokenmanager.Data[T] JSON. The user_id /
// session_id / token_type columns are denormalised at Set time so revoke
// operations don't have to scan or parse JSON.

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sxwebdev/tokenmanager"

	"github.com/sxwebdev/oblivio/internal/store/repos/repo_auth_tokens"
)

// PGTokenStore implements tokenmanager.ITokenStore over a pgx pool.
type PGTokenStore struct {
	pool *pgxpool.Pool
}

// NewPGTokenStore returns a store bound to the given pool.
func NewPGTokenStore(pool *pgxpool.Pool) *PGTokenStore {
	return &PGTokenStore{pool: pool}
}

// Compile-time interface assertion.
var _ tokenmanager.ITokenStore = (*PGTokenStore)(nil)

// tokenEnvelope mirrors the JSON shape of tokenmanager.Data[SessionData] so
// we can extract the denormalised columns without depending on the generic.
type tokenEnvelope struct {
	UserID         string    `json:"user_id"`
	IssuedAt       time.Time `json:"issued_at"`
	Expiry         time.Time `json:"expiry"`
	TokenType      string    `json:"token_type"`
	AdditionalData struct {
		SessionID  uuid.UUID `json:"session_id"`
		DeviceID   string    `json:"device_id"`
		DeviceType string    `json:"device_type"`
	} `json:"additional_data"`
}

func (s *PGTokenStore) repo() *repo_auth_tokens.Queries {
	return repo_auth_tokens.New(s.pool)
}

// Get returns the value for the given key. Returns
// tokenmanager.ErrKeyNotFound when the row is absent (or already expired —
// expired rows are filtered server-side; we surface ErrKeyExpired only on
// the rare case the row exists but expires_at <= now()). The conservative
// "missing-or-expired → not found" mapping is what tokenmanager.MemoryTokenStore
// does in practice (it deletes-on-read), so callers see equivalent semantics.
func (s *PGTokenStore) Get(ctx context.Context, key []byte) ([]byte, error) {
	row, err := s.repo().GetAuthToken(ctx, key)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, tokenmanager.ErrKeyNotFound
		}
		return nil, fmt.Errorf("pg token store: get: %w", err)
	}
	return row.Value, nil
}

// Set persists key→value with TTL. Denormalised columns are decoded from the
// value JSON so we can later revoke by user/session in O(1).
func (s *PGTokenStore) Set(ctx context.Context, key []byte, value []byte, expiration time.Duration) error {
	env, _ := decodeEnvelope(value)
	expiresAt := time.Now().Add(expiration).UTC()
	if !env.Expiry.IsZero() {
		// Trust the embedded expiry — tokenmanager sets it consistently with
		// `expiration` but using the in-payload value avoids any drift.
		expiresAt = env.Expiry.UTC()
	}
	return s.repo().UpsertAuthToken(ctx, repo_auth_tokens.UpsertAuthTokenParams{
		Key:       key,
		Value:     value,
		UserID:    nullUUIDFromString(env.UserID),
		SessionID: nullUUID(env.AdditionalData.SessionID),
		TokenType: env.TokenType,
		ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
	})
}

// Delete removes the row. No-op when missing — tokenmanager.RevokeToken
// considers a missing key a successful revoke.
func (s *PGTokenStore) Delete(ctx context.Context, key []byte) error {
	return s.repo().DeleteAuthToken(ctx, key)
}

// Keys returns non-expired keys with the given prefix.
func (s *PGTokenStore) Keys(ctx context.Context, prefix []byte) ([]string, error) {
	rows, err := s.repo().ListAuthTokensByPrefix(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("pg token store: keys: %w", err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, string(r.Key))
	}
	return out, nil
}

// KeysAndValues returns non-expired (key, value) pairs with the given prefix.
func (s *PGTokenStore) KeysAndValues(ctx context.Context, prefix []byte) (map[string][]byte, error) {
	rows, err := s.repo().ListAuthTokensByPrefix(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("pg token store: keys+values: %w", err)
	}
	out := make(map[string][]byte, len(rows))
	for _, r := range rows {
		out[string(r.Key)] = r.Value
	}
	return out, nil
}

// GetFromJSON fetches and unmarshals into dst.
func (s *PGTokenStore) GetFromJSON(ctx context.Context, key []byte, dst any) error {
	data, err := s.Get(ctx, key)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dst)
}

// SetJSON marshals and persists with TTL.
func (s *PGTokenStore) SetJSON(ctx context.Context, key []byte, value any, expiration time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return s.Set(ctx, key, data, expiration)
}

// Exists reports presence of a non-expired row.
func (s *PGTokenStore) Exists(ctx context.Context, key []byte) (bool, error) {
	return s.repo().AuthTokenExists(ctx, key)
}

// --- methods used directly by Manager (outside the ITokenStore contract) ---

// DeleteBySession removes every token bound to the given session. Used by
// Logout and TerminateSession so the access+refresh pair dies together.
func (s *PGTokenStore) DeleteBySession(ctx context.Context, sessionID uuid.UUID) error {
	return s.deleteBySessionWith(ctx, s.repo(), sessionID)
}

// DeleteBySessionTx is the in-transaction variant. Used by ChangeMasterPassword
// / RecoveryComplete which need the token revoke and the auth_sessions revoke
// to commit or roll back together (H-3): if either half fails, the wire-level
// auth state must not be partially advanced.
func (s *PGTokenStore) DeleteBySessionTx(ctx context.Context, tx pgx.Tx, sessionID uuid.UUID) error {
	return s.deleteBySessionWith(ctx, repo_auth_tokens.New(tx), sessionID)
}

func (s *PGTokenStore) deleteBySessionWith(ctx context.Context, q *repo_auth_tokens.Queries, sessionID uuid.UUID) error {
	if sessionID == uuid.Nil {
		return nil
	}
	_, err := q.DeleteAuthTokensBySession(ctx, nullUUID(sessionID))
	return err
}

// DeleteByUser removes every token belonging to userID. When exceptSessionID
// is non-nil that session's tokens are preserved (used by ChangeMasterPassword
// to keep the active browser logged in).
func (s *PGTokenStore) DeleteByUser(ctx context.Context, userID uuid.UUID, exceptSessionID *uuid.UUID) error {
	return s.deleteByUserWith(ctx, s.repo(), userID, exceptSessionID)
}

// DeleteByUserTx is the in-transaction variant. See DeleteBySessionTx (H-3).
func (s *PGTokenStore) DeleteByUserTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID, exceptSessionID *uuid.UUID) error {
	return s.deleteByUserWith(ctx, repo_auth_tokens.New(tx), userID, exceptSessionID)
}

func (s *PGTokenStore) deleteByUserWith(ctx context.Context, q *repo_auth_tokens.Queries, userID uuid.UUID, exceptSessionID *uuid.UUID) error {
	var except uuid.NullUUID
	if exceptSessionID != nil && *exceptSessionID != uuid.Nil {
		except = uuid.NullUUID{UUID: *exceptSessionID, Valid: true}
	}
	_, err := q.DeleteAuthTokensByUser(ctx, repo_auth_tokens.DeleteAuthTokensByUserParams{
		UserID:          uuid.NullUUID{UUID: userID, Valid: true},
		ExceptSessionID: except,
	})
	return err
}

// DeleteExpired sweeps rows past their expires_at. Wired into the periodic
// jobs service so the table doesn't grow without bound.
func (s *PGTokenStore) DeleteExpired(ctx context.Context) (int64, error) {
	return s.repo().DeleteExpiredAuthTokens(ctx)
}

// --- helpers ---

func decodeEnvelope(value []byte) (tokenEnvelope, bool) {
	var env tokenEnvelope
	if err := json.Unmarshal(value, &env); err != nil {
		return tokenEnvelope{}, false
	}
	return env, true
}

func nullUUIDFromString(s string) uuid.NullUUID {
	if s == "" {
		return uuid.NullUUID{}
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.NullUUID{}
	}
	return uuid.NullUUID{UUID: id, Valid: true}
}

func nullUUID(id uuid.UUID) uuid.NullUUID {
	if id == uuid.Nil {
		return uuid.NullUUID{}
	}
	return uuid.NullUUID{UUID: id, Valid: true}
}

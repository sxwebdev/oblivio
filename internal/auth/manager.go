package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/sxwebdev/tokenmanager"

	"github.com/sxwebdev/oblivio/internal/metrics"
	"github.com/sxwebdev/oblivio/internal/store"
	"github.com/sxwebdev/oblivio/internal/store/repos"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_auth_sessions"
)

// tokenmanagerKeyPrefix mirrors the unexported tokenmanager.keyPrefix. We
// derive the storage key from a signed token so the Refresh handler can
// compare it against auth_sessions.current_refresh_key for reuse detection.
const tokenmanagerKeyPrefix = "tokenmanager:"

// refreshKeyFromSignedToken returns the auth_tokens.key corresponding to the
// given signed token. The format is "tokenmanager:<payload>" where payload
// is the part of the signed token before the "." separator.
func refreshKeyFromSignedToken(signed string) []byte {
	idx := strings.IndexByte(signed, '.')
	if idx <= 0 {
		return nil
	}
	return []byte(tokenmanagerKeyPrefix + signed[:idx])
}

// IssuedTokens bundles a freshly minted access/refresh pair with their
// expiry timestamps.
type IssuedTokens struct {
	UserID           uuid.UUID
	AccessToken      string
	RefreshToken     string
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
	SessionID        uuid.UUID
	DeviceID         string
}

// ErrRefreshReuse is returned by Refresh when a refresh token is presented
// twice. Callers can use this to differentiate "bad credentials" from
// "potential token theft" — the latter triggers a full session sweep.
var ErrRefreshReuse = errors.New("auth: refresh token reused")

// Manager owns the access / refresh token issuance and the session metadata
// that backs them. The token-side state (signed JWT-like payloads) lives in
// the PG-backed PGTokenStore so revocation is authoritative across replicas.
// auth_sessions stays as the human-facing aggregate: device, ip, last seen,
// surfaced by SessionsService and used for "is this session current?" checks.
type Manager struct {
	access  *tokenmanager.Manager[SessionData]
	refresh *tokenmanager.Manager[SessionData]
	tokens  *PGTokenStore
	secrets *Secrets
	st      *store.Store

	accessTTL  time.Duration
	refreshTTL time.Duration
}

// NewManager constructs a Manager. The provided Secrets must remain alive for
// the lifetime of the Manager — the caller is responsible for Close()ing it
// on shutdown.
func NewManager(secrets *Secrets, st *store.Store, tokens *PGTokenStore, accessTTL, refreshTTL time.Duration) *Manager {
	return &Manager{
		access:     tokenmanager.New[SessionData](tokens, secrets.AccessSecret(), accessTTL),
		refresh:    tokenmanager.New[SessionData](tokens, secrets.RefreshSecret(), refreshTTL),
		tokens:     tokens,
		secrets:    secrets,
		st:         st,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}
}

// Issue creates (or reuses) a session row and mints a fresh token pair bound
// to it. The session row is upserted FIRST so we can stamp its real id into
// the token payload — without this Logout/TerminateSession look up the row
// by the wrong uuid and silently no-op.
func (m *Manager) Issue(ctx context.Context, userID uuid.UUID, deviceID, deviceType, deviceName string) (IssuedTokens, error) {
	if deviceID == "" {
		return IssuedTokens{}, errors.New("device_id required")
	}

	var sessionRow uuid.UUID
	if err := m.st.SystemDo(ctx, func(tx pgx.Tx) error {
		r, err := m.st.AuthSessions(repos.WithTx(tx)).UpsertSession(ctx, repo_auth_sessions.UpsertSessionParams{
			UserID:           userID,
			DeviceID:         deviceID,
			DeviceType:       deviceType,
			DeviceName:       textOrNull(deviceName),
			AccessExpiresAt:  pgtype.Timestamptz{Time: time.Now().Add(m.accessTTL), Valid: true},
			RefreshExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(m.refreshTTL), Valid: true},
		})
		if err != nil {
			return fmt.Errorf("persist session: %w", err)
		}
		sessionRow = r.ID
		return nil
	}); err != nil {
		return IssuedTokens{}, err
	}

	// Drop any pre-existing tokens bound to this session — happens on
	// re-login from the same device. Without it the previous access/refresh
	// would stay valid until natural expiry. auth_tokens has no RLS so a
	// plain call works.
	if err := m.tokens.DeleteBySession(ctx, sessionRow); err != nil {
		return IssuedTokens{}, fmt.Errorf("clear stale tokens: %w", err)
	}

	data := SessionData{SessionID: sessionRow, DeviceID: deviceID, DeviceType: deviceType}

	accessTok, accessMeta, err := m.access.CreateToken(ctx, userID.String(), data, tokenmanager.AccessTokenType)
	if err != nil {
		return IssuedTokens{}, fmt.Errorf("issue access: %w", err)
	}
	refreshTok, refreshMeta, err := m.refresh.CreateToken(ctx, userID.String(), data, tokenmanager.RefreshTokenType)
	if err != nil {
		_ = m.access.RevokeToken(ctx, accessTok)
		return IssuedTokens{}, fmt.Errorf("issue refresh: %w", err)
	}

	// Stamp the just-issued refresh's storage key so Refresh can detect
	// presentation of an older refresh and treat it as theft.
	if err := m.st.SystemDo(ctx, func(tx pgx.Tx) error {
		return m.st.AuthSessions(repos.WithTx(tx)).SetSessionCurrentRefreshKey(ctx, repo_auth_sessions.SetSessionCurrentRefreshKeyParams{
			ID:                sessionRow,
			CurrentRefreshKey: refreshKeyFromSignedToken(refreshTok),
		})
	}); err != nil {
		_ = m.access.RevokeToken(ctx, accessTok)
		_ = m.refresh.RevokeToken(ctx, refreshTok)
		return IssuedTokens{}, fmt.Errorf("stamp current refresh: %w", err)
	}

	return IssuedTokens{
		UserID:           userID,
		AccessToken:      accessTok,
		RefreshToken:     refreshTok,
		AccessExpiresAt:  accessMeta.Expiry,
		RefreshExpiresAt: refreshMeta.Expiry,
		SessionID:        sessionRow,
		DeviceID:         deviceID,
	}, nil
}

// Authenticate validates an access token and returns the associated session
// metadata. Used by the auth middleware. A revoked token returns
// (nil, error) because the underlying PG row is gone.
func (m *Manager) Authenticate(ctx context.Context, accessToken string) (*tokenmanager.Data[SessionData], error) {
	data, ok := m.access.ValidateToken(ctx, accessToken, tokenmanager.AccessTokenType)
	if !ok {
		return nil, errors.New("invalid access token")
	}
	return data, nil
}

// Refresh rotates a refresh token, returning a brand-new access+refresh pair
// and revoking the old ones.
//
// Reuse detection: every Issue stamps the just-minted refresh's storage key
// into auth_sessions.current_refresh_key. On Refresh we compare the
// presented refresh's derived key with the stamp; a mismatch means an OLDER
// refresh was presented (token theft) and we burn every active token for
// the user → caller sees ErrRefreshReuse.
func (m *Manager) Refresh(ctx context.Context, refreshToken, deviceType, deviceName string) (IssuedTokens, error) {
	data, ok := m.refresh.ValidateToken(ctx, refreshToken, tokenmanager.RefreshTokenType)
	if !ok {
		return IssuedTokens{}, errors.New("invalid refresh token")
	}

	userID, err := uuid.Parse(data.UserID)
	if err != nil {
		return IssuedTokens{}, fmt.Errorf("invalid user id in token: %w", err)
	}

	presentedKey := refreshKeyFromSignedToken(refreshToken)
	var currentKey []byte
	if err := m.st.SystemDo(ctx, func(tx pgx.Tx) error {
		k, err := m.st.AuthSessions(repos.WithTx(tx)).GetSessionCurrentRefreshKey(ctx, data.AdditionalData.SessionID)
		if err != nil {
			return err
		}
		currentKey = k
		return nil
	}); err != nil {
		return IssuedTokens{}, fmt.Errorf("read current refresh key: %w", err)
	}
	if !bytes.Equal(currentKey, presentedKey) {
		// The presented refresh is not the latest one issued for this
		// session → token theft. Burn everything.
		_ = m.tokens.DeleteByUser(ctx, userID, nil)
		_ = m.st.SystemDo(ctx, func(tx pgx.Tx) error {
			return m.st.AuthSessions(repos.WithTx(tx)).RevokeAllUserSessions(ctx, userID)
		})
		metrics.RefreshAttemptsTotal.WithLabelValues("reuse").Inc()
		return IssuedTokens{}, ErrRefreshReuse
	}

	// Revoke old refresh AND the access token bound to the same session.
	// Issue() will re-stamp a fresh pair against the same auth_sessions row.
	_ = m.refresh.RevokeToken(ctx, refreshToken)
	_ = m.tokens.DeleteBySession(ctx, data.AdditionalData.SessionID)

	dt := deviceType
	if dt == "" {
		dt = data.AdditionalData.DeviceType
	}
	return m.Issue(ctx, userID, data.AdditionalData.DeviceID, dt, deviceName)
}

// RevokeAllUserTokens deletes every token row for the user. Used by
// RecoveryComplete and account deletion.
func (m *Manager) RevokeAllUserTokens(ctx context.Context, userID uuid.UUID) error {
	return m.tokens.DeleteByUser(ctx, userID, nil)
}

// RevokeUserTokensExceptSession deletes every token row for the user except
// those bound to exceptSessionID. Used by ChangeMasterPassword to keep the
// caller logged in while burning the rest.
func (m *Manager) RevokeUserTokensExceptSession(ctx context.Context, userID, exceptSessionID uuid.UUID) error {
	return m.tokens.DeleteByUser(ctx, userID, &exceptSessionID)
}

// Logout revokes both tokens of the active session and marks the
// auth_sessions row revoked.
func (m *Manager) Logout(ctx context.Context, accessToken string) error {
	data, ok := m.access.ValidateToken(ctx, accessToken, tokenmanager.AccessTokenType)
	if !ok {
		// Access token already invalid — nothing to do. Caller treats as success.
		return nil
	}
	// Burn the whole session: removes both access and refresh rows. After
	// this the refresh token can no longer be exchanged for a new pair.
	if err := m.tokens.DeleteBySession(ctx, data.AdditionalData.SessionID); err != nil {
		return fmt.Errorf("delete session tokens: %w", err)
	}
	if err := m.st.SystemDo(ctx, func(tx pgx.Tx) error {
		return m.st.AuthSessions(repos.WithTx(tx)).RevokeSession(ctx, data.AdditionalData.SessionID)
	}); err != nil {
		return fmt.Errorf("revoke session row: %w", err)
	}
	return nil
}

// RevokeSession kills both tokens for the given session id and marks the
// auth_sessions row revoked. Called by SessionsService.TerminateSession.
func (m *Manager) RevokeSession(ctx context.Context, sessionID uuid.UUID) error {
	if err := m.tokens.DeleteBySession(ctx, sessionID); err != nil {
		return fmt.Errorf("delete session tokens: %w", err)
	}
	return m.st.SystemDo(ctx, func(tx pgx.Tx) error {
		return m.st.AuthSessions(repos.WithTx(tx)).RevokeSession(ctx, sessionID)
	})
}

// TokenStore exposes the underlying PG store so periodic jobs (GC) can use
// it directly.
func (m *Manager) TokenStore() *PGTokenStore { return m.tokens }

func textOrNull(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}

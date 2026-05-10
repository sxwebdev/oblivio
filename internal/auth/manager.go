package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/sxwebdev/tokenmanager"

	"github.com/sxwebdev/oblivio/internal/store"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_auth_sessions"
)

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

// Manager is the public façade over access/refresh token issuance and
// session persistence. It owns two tokenmanager.Manager instances (one per
// token type) plus a thin layer that mirrors session state into auth_sessions
// so it survives across restarts and is visible in the UI.
type Manager struct {
	access       *tokenmanager.Manager[SessionData]
	refresh      *tokenmanager.Manager[SessionData]
	accessStore  *tokenmanager.MemoryTokenStore
	refreshStore *tokenmanager.MemoryTokenStore
	secrets      *Secrets
	st           *store.Store

	accessTTL  time.Duration
	refreshTTL time.Duration
}

// NewManager constructs a Manager. The provided Secrets must remain alive for
// the lifetime of the Manager — the caller is responsible for Close()ing it
// on shutdown.
func NewManager(secrets *Secrets, st *store.Store, accessTTL, refreshTTL time.Duration) *Manager {
	accessStore := tokenmanager.NewMemoryTokenStore()
	refreshStore := tokenmanager.NewMemoryTokenStore()
	return &Manager{
		access:       tokenmanager.New[SessionData](accessStore, secrets.AccessSecret(), accessTTL),
		refresh:      tokenmanager.New[SessionData](refreshStore, secrets.RefreshSecret(), refreshTTL),
		accessStore:  accessStore,
		refreshStore: refreshStore,
		secrets:      secrets,
		st:           st,
		accessTTL:    accessTTL,
		refreshTTL:   refreshTTL,
	}
}

// Issue creates a new session and a fresh token pair. Repeated Issue calls
// for the same (user_id, device_id) replace the previous session via upsert.
func (m *Manager) Issue(ctx context.Context, userID uuid.UUID, deviceID, deviceType, deviceName string) (IssuedTokens, error) {
	if deviceID == "" {
		return IssuedTokens{}, errors.New("device_id required")
	}

	sessionID := uuid.New()
	data := SessionData{SessionID: sessionID, DeviceID: deviceID, DeviceType: deviceType}

	accessTok, accessMeta, err := m.access.CreateToken(ctx, userID.String(), data, tokenmanager.AccessTokenType)
	if err != nil {
		return IssuedTokens{}, fmt.Errorf("issue access: %w", err)
	}
	refreshTok, refreshMeta, err := m.refresh.CreateToken(ctx, userID.String(), data, tokenmanager.RefreshTokenType)
	if err != nil {
		_ = m.access.RevokeToken(ctx, accessTok)
		return IssuedTokens{}, fmt.Errorf("issue refresh: %w", err)
	}

	row, err := m.st.AuthSessions().UpsertSession(ctx, repo_auth_sessions.UpsertSessionParams{
		UserID:           userID,
		DeviceID:         deviceID,
		DeviceType:       deviceType,
		DeviceName:       textOrNull(deviceName),
		AccessTokenHash:  TokenHash(accessTok),
		RefreshTokenHash: TokenHash(refreshTok),
		AccessExpiresAt:  pgtype.Timestamptz{Time: accessMeta.Expiry, Valid: true},
		RefreshExpiresAt: pgtype.Timestamptz{Time: refreshMeta.Expiry, Valid: true},
	})
	if err != nil {
		_ = m.access.RevokeToken(ctx, accessTok)
		_ = m.refresh.RevokeToken(ctx, refreshTok)
		return IssuedTokens{}, fmt.Errorf("persist session: %w", err)
	}

	return IssuedTokens{
		UserID:           userID,
		AccessToken:      accessTok,
		RefreshToken:     refreshTok,
		AccessExpiresAt:  accessMeta.Expiry,
		RefreshExpiresAt: refreshMeta.Expiry,
		SessionID:        row.ID,
		DeviceID:         deviceID,
	}, nil
}

// Authenticate validates an access token and returns the associated session
// metadata. Used by the auth middleware.
func (m *Manager) Authenticate(ctx context.Context, accessToken string) (*tokenmanager.Data[SessionData], error) {
	data, ok := m.access.ValidateToken(ctx, accessToken, tokenmanager.AccessTokenType)
	if !ok {
		return nil, errors.New("invalid access token")
	}
	return data, nil
}

// Refresh rotates a refresh token, returning a brand-new access+refresh pair
// and revoking the old ones. The session row is updated in place.
func (m *Manager) Refresh(ctx context.Context, refreshToken, deviceType, deviceName string) (IssuedTokens, error) {
	data, ok := m.refresh.ValidateToken(ctx, refreshToken, tokenmanager.RefreshTokenType)
	if !ok {
		return IssuedTokens{}, errors.New("invalid refresh token")
	}

	userID, err := uuid.Parse(data.UserID)
	if err != nil {
		return IssuedTokens{}, fmt.Errorf("invalid user id in token: %w", err)
	}

	// Revoke old pair before issuing the new one. If issuance fails the user
	// must re-authenticate — this is preferable to leaving two valid refresh
	// tokens alive simultaneously.
	_ = m.refresh.RevokeToken(ctx, refreshToken)

	dt := deviceType
	if dt == "" {
		dt = data.AdditionalData.DeviceType
	}
	return m.Issue(ctx, userID, data.AdditionalData.DeviceID, dt, deviceName)
}

// RevokeAllUserTokens deletes every access/refresh token still held by the
// in-memory tokenmanager store for the given user. Used by RecoveryComplete
// and "terminate all sessions" so a leaked password+code combination cannot
// resurrect itself through still-valid signatures.
//
// The store is scanned linearly; for the expected fleet size (single-digit
// devices per user, low single-digit QPS for auth) this is fine.
func (m *Manager) RevokeAllUserTokens(ctx context.Context, userID uuid.UUID) error {
	if err := revokeAllInStore(ctx, m.accessStore, userID); err != nil {
		return fmt.Errorf("revoke access tokens: %w", err)
	}
	if err := revokeAllInStore(ctx, m.refreshStore, userID); err != nil {
		return fmt.Errorf("revoke refresh tokens: %w", err)
	}
	return nil
}

// Logout revokes the access token (and any cached state in tokenmanager) and
// marks the associated auth_sessions row revoked.
func (m *Manager) Logout(ctx context.Context, accessToken string) error {
	data, ok := m.access.ValidateToken(ctx, accessToken, tokenmanager.AccessTokenType)
	if !ok {
		// Already invalid — treat as success.
		return nil
	}
	_ = m.access.RevokeToken(ctx, accessToken)
	if err := m.st.AuthSessions().RevokeSession(ctx, data.AdditionalData.SessionID); err != nil {
		return fmt.Errorf("revoke session row: %w", err)
	}
	return nil
}

func textOrNull(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}

// revokeAllInStore iterates the in-memory token store and deletes any entry
// whose embedded user_id matches `userID`. The store keys tokens by a hex
// payload — there is no per-user index — so this is O(N) over live tokens.
// For the expected fleet size that cost is negligible.
func revokeAllInStore(ctx context.Context, store *tokenmanager.MemoryTokenStore, userID uuid.UUID) error {
	entries, err := store.KeysAndValues(ctx, nil)
	if err != nil {
		return err
	}
	want := userID.String()
	for k, v := range entries {
		var td tokenmanager.Data[SessionData]
		if err := json.Unmarshal(v, &td); err != nil {
			continue // skip unparseable entries; expired sweep will remove them
		}
		if td.UserID != want {
			continue
		}
		if err := store.Delete(ctx, []byte(k)); err != nil {
			return err
		}
	}
	return nil
}

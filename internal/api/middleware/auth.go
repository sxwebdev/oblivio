// Package middleware contains cross-cutting HTTP/Connect-RPC middleware.
package middleware

import (
	"context"
	"net/http"
	"strings"

	"connectrpc.com/authn"
	"github.com/google/uuid"

	"github.com/sxwebdev/oblivio/internal/auth"
)

// userCtxKey is the type for the user-context value attached after a
// successful authentication.
type userCtxKey struct{}

// UserContext carries the authenticated principal across handlers.
type UserContext struct {
	UserID      uuid.UUID
	SessionID   uuid.UUID
	DeviceID    string
	AccessToken string
}

// FromContext extracts the UserContext if present. The second return value is
// false when the request was anonymous.
func FromContext(ctx context.Context) (*UserContext, bool) {
	v := authn.GetInfo(ctx)
	uc, ok := v.(*UserContext)
	return uc, ok
}

// MustFromContext returns the authenticated UserContext or panics. Only call
// this from handlers that are *not* on the anonymous allowlist.
func MustFromContext(ctx context.Context) *UserContext {
	uc, ok := FromContext(ctx)
	if !ok {
		panic("authenticated user not present in context")
	}
	return uc
}

// AnonymousProcedures lists the fully-qualified RPC procedure names that may
// be invoked without a Bearer token. Anything else requires authentication.
// The list is intentionally small and explicit — a missing entry fails
// closed (returns UNAUTHENTICATED).
var AnonymousProcedures = map[string]struct{}{
	"/oblivio.v1.AuthService/Register":          {},
	"/oblivio.v1.AuthService/GetKDFParams":      {},
	"/oblivio.v1.AuthService/Authorize":         {},
	"/oblivio.v1.AuthService/CompleteMFA":       {},
	"/oblivio.v1.AuthService/RefreshToken":      {},
	"/oblivio.v1.AuthService/GetRecoveryParams": {},
	"/oblivio.v1.AuthService/RecoveryStart":     {},
	"/oblivio.v1.AuthService/RecoveryComplete":  {},
}

// NewAuthMiddleware returns a connectrpc/authn middleware that:
//   - Lets anonymous procedures through without inspection.
//   - For all other procedures, requires `Authorization: Bearer <token>` and
//     validates the token via the auth.Manager.
//
// On success the *UserContext is attached to the request context.
func NewAuthMiddleware(am *auth.Manager) *authn.Middleware {
	return authn.NewMiddleware(func(ctx context.Context, req *http.Request) (any, error) {
		procedure, _ := authn.InferProcedure(req.URL)
		if _, ok := AnonymousProcedures[procedure]; ok {
			return nil, nil
		}

		token := bearerToken(req)
		if token == "" {
			return nil, authn.Errorf("missing bearer token")
		}
		data, err := am.Authenticate(ctx, token)
		if err != nil {
			return nil, authn.Errorf("invalid bearer token")
		}
		userID, err := uuid.Parse(data.UserID)
		if err != nil {
			return nil, authn.Errorf("invalid user id in token")
		}
		return &UserContext{
			UserID:      userID,
			SessionID:   data.AdditionalData.SessionID,
			DeviceID:    data.AdditionalData.DeviceID,
			AccessToken: token,
		}, nil
	})
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// Package vault implements the VaultService ConnectRPC handler.
//
// VaultService exposes per-user account metadata: stable user_id, the
// verified-email flag, and 2-factor status. The destructive DeleteMe path
// is planned for Sprint 4 (crypto-shred).
package vault

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"

	pb "github.com/sxwebdev/oblivio/internal/api/gen/go/oblivio/v1"
	"github.com/sxwebdev/oblivio/internal/api/gen/go/oblivio/v1/obliviov1connect"
	"github.com/sxwebdev/oblivio/internal/api/middleware"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_user_login_totp"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_users"
)

// Service implements VaultService.
type Service struct {
	obliviov1connect.UnimplementedVaultServiceHandler
}

// NewService constructs the handler. Stateless — uses the per-request tx.
func NewService() *Service { return &Service{} }

// GetMe returns enough metadata for the client to bootstrap its UI:
// stable user_id (needed as the AAD vault scope), email, verification
// flag and TOTP / WebAuthn status.
func (s *Service) GetMe(ctx context.Context, _ *connect.Request[pb.GetMeRequest]) (*connect.Response[pb.GetMeResponse], error) {
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)

	u, err := repo_users.New(tx).GetUserByID(ctx, uc.UserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	totpEnabled := false
	if t, err := repo_user_login_totp.New(tx).GetUserLoginTOTP(ctx, uc.UserID); err == nil && t != nil {
		totpEnabled = t.Enabled
	} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	// WebAuthn credentials land in Sprint 3; report zero for now.
	return connect.NewResponse(&pb.GetMeResponse{
		UserId:                   u.ID.String(),
		Email:                    u.Email,
		EmailVerified:            u.EmailVerifiedAt.Valid,
		TotpEnabled:              totpEnabled,
		WebauthnCredentialsCount: 0,
	}), nil
}

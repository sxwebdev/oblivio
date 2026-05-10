// Package vault implements the VaultService ConnectRPC handler.
//
// VaultService exposes per-user account metadata and the destructive
// DeleteMe path (crypto-shred). The latter physically removes every
// user-owned row and revokes all sessions; surviving backups become
// undecryptable because wrapped_vault_key disappears with the user_vault
// row (plan §6.8).
package vault

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	pb "github.com/sxwebdev/oblivio/internal/api/gen/go/oblivio/v1"
	"github.com/sxwebdev/oblivio/internal/api/gen/go/oblivio/v1/obliviov1connect"
	"github.com/sxwebdev/oblivio/internal/api/middleware"
	"github.com/sxwebdev/oblivio/internal/audit"
	"github.com/sxwebdev/oblivio/internal/auth"
	"github.com/sxwebdev/oblivio/internal/metrics"
	"github.com/sxwebdev/oblivio/internal/models"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_user_login_totp"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_user_webauthn_credentials"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_users"
)

// Service implements VaultService.
type Service struct {
	obliviov1connect.UnimplementedVaultServiceHandler
	am          *auth.Manager
	auditWriter *audit.Writer
}

// Deps groups constructor arguments. Both AuthManager and AuditWriter are
// required for DeleteMe to function correctly; GetMe works without them.
type Deps struct {
	AuthManager *auth.Manager
	AuditWriter *audit.Writer
}

// NewService constructs the handler.
func NewService(d Deps) *Service {
	return &Service{am: d.AuthManager, auditWriter: d.AuditWriter}
}

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

	credCount, err := repo_user_webauthn_credentials.New(tx).CountWebAuthnCredentials(ctx, uc.UserID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&pb.GetMeResponse{
		UserId:                   u.ID.String(),
		Email:                    u.Email,
		EmailVerified:            u.EmailVerifiedAt.Valid,
		TotpEnabled:              totpEnabled,
		WebauthnCredentialsCount: uint32(credCount), //nolint:gosec
	}), nil
}

// DeleteMe wipes the caller's account and every row that references it via
// CASCADE. After the row in user_vault disappears, the ciphertext that may
// linger in backups is unrecoverable (no wrapped_vault_key, no recovery
// proof). The audit row is written BEFORE the user delete so the event
// survives in the chain (audit_log.user_id uses ON DELETE SET NULL).
func (s *Service) DeleteMe(ctx context.Context, req *connect.Request[pb.DeleteMeRequest]) (*connect.Response[pb.DeleteMeResponse], error) {
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)

	// Audit must run before the cascade so the user_id is still valid on
	// the FK lookup. Failure to write the audit row is fatal — silent
	// account deletion is worse than aborting.
	if s.auditWriter != nil {
		ev := audit.Event{
			UserID:    uuid.NullUUID{UUID: uc.UserID, Valid: true},
			TargetID:  uuid.NullUUID{UUID: uc.UserID, Valid: true},
			Action:    models.AuditActionAccountDelete,
			UserAgent: req.Header().Get("User-Agent"),
			Metadata: map[string]any{
				"procedure": req.Spec().Procedure,
				"reason":    req.Msg.Reason,
				"device_id": uc.DeviceID,
			},
		}
		if _, err := s.auditWriter.Append(ctx, ev); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
	}

	// CASCADE removes user_kdf_params, user_auth, user_vault,
	// user_login_totp, user_webauthn_credentials, auth_sessions,
	// projects, entries, idempotency_keys. audit_log.user_id is set to
	// NULL (the chain row persists, but no longer attributable).
	if err := repo_users.New(tx).DeleteUser(ctx, uc.UserID); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	// Burn the in-memory token store too. RLS-tx commit happens after
	// the handler returns, but the in-memory map is independent of the
	// DB transaction so it is safe to clear now.
	if s.am != nil {
		_ = s.am.RevokeAllUserTokens(ctx, uc.UserID)
	}
	metrics.SessionsTerminatedTotal.WithLabelValues("delete_me").Inc()

	return connect.NewResponse(&pb.DeleteMeResponse{}), nil
}

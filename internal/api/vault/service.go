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

// DeleteMe wipes the caller's account. Every dependent row is removed via
// FK CASCADE (auth_sessions, auth_tokens, projects, entries, vault key
// wrappers, webauthn credentials, login_totp, idempotency). audit_log
// keeps the row but its user_id stays as a bare UUID without referential
// integrity (the chain hash includes user_id and ON DELETE SET NULL would
// silently break verification — see migration 004).
//
// All side-effects ride the request's RLS transaction so a failure mid-
// way rolls back atomically. The audit row is written via the writer's
// own (system) tx so it survives even if the outer rollback wipes the
// user — that's the desired behaviour for a tamper-evident chain.
func (s *Service) DeleteMe(ctx context.Context, req *connect.Request[pb.DeleteMeRequest]) (*connect.Response[pb.DeleteMeResponse], error) {
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)

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

	if err := repo_users.New(tx).DeleteUser(ctx, uc.UserID); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	metrics.SessionsTerminatedTotal.WithLabelValues("delete_me").Inc()

	return connect.NewResponse(&pb.DeleteMeResponse{}), nil
}

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
	"strings"

	"connectrpc.com/connect"
	wa "github.com/go-webauthn/webauthn/webauthn"
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
	wa          *wa.WebAuthn
	mfa         *auth.MFAStore
}

// Deps groups constructor arguments. AuthManager and AuditWriter are
// always required; WebAuthn / MFAStore are required only when DeleteMe
// must validate a passkey assertion (i.e. the caller has ≥1 enrolled
// credential) — if absent and the caller has a passkey, DeleteMe fails
// with FailedPrecondition.
type Deps struct {
	AuthManager *auth.Manager
	AuditWriter *audit.Writer
	WebAuthn    *wa.WebAuthn
	MFAStore    *auth.MFAStore
}

// NewService constructs the handler.
func NewService(d Deps) *Service {
	return &Service{
		am:          d.AuthManager,
		auditWriter: d.AuditWriter,
		wa:          d.WebAuthn,
		mfa:         d.MFAStore,
	}
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

// connectMsg returns the short, public-facing message of a Connect error
// for inclusion in audit metadata. Internal-only errors are flattened to
// their plain Error() string. Avoids leaking stack info or low-level DB
// details into the chain, but keeps the rejection reason useful for
// forensics.
func connectMsg(err error) string {
	if err == nil {
		return ""
	}
	var cerr *connect.Error
	if errors.As(err, &cerr) {
		return cerr.Message()
	}
	return err.Error()
}

// DeleteMe wipes the caller's account. Every dependent row is removed via
// FK CASCADE (auth_sessions, auth_tokens, projects, entries, vault key
// wrappers, webauthn credentials, login_totp, idempotency). audit_log
// keeps the row but its user_id stays as a bare UUID without referential
// integrity (the chain hash includes user_id and ON DELETE SET NULL would
// silently break verification — see migration 004).
//
// Authentication: a stolen access token must not be able to crypto-shred
// the account. We require the caller to re-prove the master password
// (auth_key) AND every 2FA factor they have enrolled — a fresh TOTP code
// when login_totp.enabled and a fresh WebAuthn assertion when ≥1 passkey
// is registered. All checks run before any data is touched and before
// the audit row is appended.
func (s *Service) DeleteMe(ctx context.Context, req *connect.Request[pb.DeleteMeRequest]) (*connect.Response[pb.DeleteMeResponse], error) {
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)
	r := req.Msg

	// Log every failed delete attempt before returning so the audit chain
	// shows probes of the crypto-shred path. The audit writer uses its own
	// system tx, so the row survives even though the outer request tx
	// rolls back on the error we return immediately afterwards.
	logFailure := func(stage, reason string) {
		if s.auditWriter == nil {
			return
		}
		_, _ = s.auditWriter.Append(ctx, audit.Event{
			UserID:    uuid.NullUUID{UUID: uc.UserID, Valid: true},
			TargetID:  uuid.NullUUID{UUID: uc.UserID, Valid: true},
			Action:    models.AuditActionAccountDeleteAttemptFailed,
			UserAgent: req.Header().Get("User-Agent"),
			Metadata: map[string]any{
				"procedure": req.Spec().Procedure,
				"stage":     stage,
				"reason":    reason,
				"device_id": uc.DeviceID,
			},
		})
	}

	if err := auth.VerifyUserAuthKey(ctx, tx, uc.UserID, r.AuthKey); err != nil {
		logFailure("auth_key", connectMsg(err))
		return nil, err
	}

	totpRow, err := repo_user_login_totp.New(tx).GetUserLoginTOTP(ctx, uc.UserID)
	switch {
	case err == nil && totpRow != nil && totpRow.Enabled:
		if strings.TrimSpace(r.TotpCode) == "" {
			logFailure("totp", "missing")
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("totp_code required"))
		}
		secret, err := auth.OpenLoginTOTPSecret(r.AuthKey, totpRow.EncryptedSecret)
		if err != nil {
			logFailure("totp", "secret_corrupt")
			return nil, connect.NewError(connect.CodeInternal, errors.New("totp secret corrupted"))
		}
		defer secret.Destroy()
		if err := auth.ValidateTOTPCodeBytes(secret.Bytes(), []byte(r.TotpCode)); err != nil {
			logFailure("totp", "invalid")
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid totp code"))
		}
	case err != nil && !errors.Is(err, pgx.ErrNoRows):
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	credCount, err := repo_user_webauthn_credentials.New(tx).CountWebAuthnCredentials(ctx, uc.UserID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if credCount > 0 {
		if len(r.WebauthnAssertionJson) == 0 || strings.TrimSpace(r.MfaSessionId) == "" {
			logFailure("passkey", "missing")
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("webauthn_assertion_json and mfa_session_id required"))
		}
		if _, err := auth.ConsumeWebAuthnAssertion(ctx, tx, s.wa, s.mfa, uc.UserID, r.MfaSessionId, r.WebauthnAssertionJson); err != nil {
			logFailure("passkey", connectMsg(err))
			return nil, err
		}
	}

	// All factors verified. Append the audit row first (uses the writer's
	// own system tx so it survives the cascading delete that follows) and
	// then perform the delete.
	if s.auditWriter != nil {
		ev := audit.Event{
			UserID:    uuid.NullUUID{UUID: uc.UserID, Valid: true},
			TargetID:  uuid.NullUUID{UUID: uc.UserID, Valid: true},
			Action:    models.AuditActionAccountDelete,
			UserAgent: req.Header().Get("User-Agent"),
			Metadata: map[string]any{
				"procedure": req.Spec().Procedure,
				"reason":    r.Reason,
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

// Package login_totp implements the LoginTOTPService ConnectRPC handler.
//
// The handler enforces plan §5.3: TOTP secrets are encrypted client-side
// under K_login_totp = HKDF(auth_key, "oblivio/login-totp/v1"). The server
// receives auth_key on every Setup/Enable/Disable call, derives K_login_totp
// into a memguard buffer, decrypts the secret to validate the supplied
// totp_code, and wipes the buffer before returning. Stored ciphertext +
// nonce never leak the secret.
package login_totp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	"github.com/awnumar/memguard"
	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	pb "github.com/sxwebdev/oblivio/internal/api/gen/go/oblivio/v1"
	"github.com/sxwebdev/oblivio/internal/api/gen/go/oblivio/v1/obliviov1connect"
	"github.com/sxwebdev/oblivio/internal/api/middleware"
	"github.com/sxwebdev/oblivio/internal/auth"
	"github.com/sxwebdev/oblivio/internal/auth/wauser"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_user_login_totp"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_user_webauthn_credentials"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_users"
)

// Service implements LoginTOTPService.
type Service struct {
	obliviov1connect.UnimplementedLoginTOTPServiceHandler
	wa  *wa.WebAuthn
	mfa *auth.MFAStore
}

// NewService constructs the handler. wa/mfa may be nil — Disable's
// webauthn fallback path is then unavailable but the TOTP path still works.
func NewService(rp *wa.WebAuthn, mfa *auth.MFAStore) *Service {
	return &Service{wa: rp, mfa: mfa}
}

// consumeWebAuthnAssertion validates the assertion against the challenge
// previously seeded by WebAuthnService.BeginAssertion and bumps sign_count.
func (s *Service) consumeWebAuthnAssertion(ctx context.Context, tx pgx.Tx, userID uuid.UUID, sessionID string, assertion []byte) error {
	sid, err := uuid.Parse(sessionID)
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("invalid mfa_session_id"))
	}
	ch, err := s.mfa.Take(ctx, sid)
	if err != nil {
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("mfa challenge expired"))
	}
	if ch.UserID != userID || ch.WebAuthnState == nil {
		return connect.NewError(connect.CodePermissionDenied, errors.New("session does not belong to caller"))
	}

	u, err := repo_users.New(tx).GetUserByID(ctx, userID)
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	creds, err := repo_user_webauthn_credentials.New(tx).ListWebAuthnCredentials(ctx, userID)
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}

	wuser := wauser.FromIdentity(u.ID, u.Email, creds)

	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(assertion))
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("parse assertion: %w", err))
	}
	credential, err := s.wa.ValidateLogin(wuser, *ch.WebAuthnState, parsed)
	if err != nil {
		return connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("webauthn validate: %w", err))
	}
	matched, err := repo_user_webauthn_credentials.New(tx).GetWebAuthnCredentialByCredID(ctx, credential.ID)
	if err == nil {
		_ = repo_user_webauthn_credentials.New(tx).TouchWebAuthnCredential(ctx, repo_user_webauthn_credentials.TouchWebAuthnCredentialParams{
			ID:        matched.ID,
			SignCount: int64(credential.Authenticator.SignCount),
			Flags:     int16(credential.Flags.ProtocolValue()), //nolint:gosec
		})
	}
	return nil
}

// Setup uploads a freshly-encrypted secret. The server derives K_login_totp,
// decrypts the secret, validates the supplied code, then persists the
// envelope in user_login_totp with `enabled = false`.
func (s *Service) Setup(ctx context.Context, req *connect.Request[pb.LoginTOTPServiceSetupRequest]) (*connect.Response[pb.LoginTOTPServiceSetupResponse], error) {
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)
	r := req.Msg

	if len(r.AuthKey) == 0 || len(r.EncryptedSecret) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("auth_key and encrypted_secret required"))
	}
	if err := s.verifyAuthKey(ctx, tx, uc, r.AuthKey); err != nil {
		return nil, err
	}

	secretBuf, err := decryptLoginTOTP(r.AuthKey, r.EncryptedSecret)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	defer secretBuf.Destroy()

	if err := auth.ValidateTOTPCodeBytes(secretBuf.Bytes(), []byte(r.TotpCode)); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("totp code does not match the supplied secret"))
	}

	if err := repo_user_login_totp.New(tx).UpsertUserLoginTOTP(ctx, repo_user_login_totp.UpsertUserLoginTOTPParams{
		UserID:          uc.UserID,
		EncryptedSecret: r.EncryptedSecret,
		Nonce:           r.Nonce,
		Enabled:         false,
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&pb.LoginTOTPServiceSetupResponse{}), nil
}

// Enable activates the previously-uploaded secret as a login factor.
func (s *Service) Enable(ctx context.Context, req *connect.Request[pb.LoginTOTPServiceEnableRequest]) (*connect.Response[pb.LoginTOTPServiceEnableResponse], error) {
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)

	if err := s.verifyAuthKey(ctx, tx, uc, req.Msg.AuthKey); err != nil {
		return nil, err
	}
	row, err := repo_user_login_totp.New(tx).GetUserLoginTOTP(ctx, uc.UserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("totp not configured"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	secret, err := decryptLoginTOTP(req.Msg.AuthKey, row.EncryptedSecret)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("totp secret corrupted"))
	}
	defer secret.Destroy()
	if err := auth.ValidateTOTPCodeBytes(secret.Bytes(), []byte(req.Msg.TotpCode)); err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid totp code"))
	}
	if err := repo_user_login_totp.New(tx).UpsertUserLoginTOTP(ctx, repo_user_login_totp.UpsertUserLoginTOTPParams{
		UserID:          uc.UserID,
		EncryptedSecret: row.EncryptedSecret,
		Nonce:           row.Nonce,
		Enabled:         true,
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	middleware.SetAuditTarget(ctx, uc.UserID)
	return connect.NewResponse(&pb.LoginTOTPServiceEnableResponse{}), nil
}

// Disable removes the stored secret entirely. Accepts EITHER a fresh TOTP
// code OR a WebAuthn assertion (for users who lost their authenticator
// app). The auth_key check is mandatory in both paths so a stolen access
// token alone can't downgrade 2FA.
func (s *Service) Disable(ctx context.Context, req *connect.Request[pb.LoginTOTPServiceDisableRequest]) (*connect.Response[pb.LoginTOTPServiceDisableResponse], error) {
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)
	r := req.Msg

	if err := s.verifyAuthKey(ctx, tx, uc, r.AuthKey); err != nil {
		return nil, err
	}
	row, err := repo_user_login_totp.New(tx).GetUserLoginTOTP(ctx, uc.UserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return connect.NewResponse(&pb.LoginTOTPServiceDisableResponse{}), nil
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	hasTOTP := strings.TrimSpace(r.TotpCode) != ""
	hasWA := len(r.WebauthnAssertionJson) > 0 && strings.TrimSpace(r.MfaSessionId) != ""
	if hasTOTP == hasWA {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("provide exactly one of totp_code or webauthn_assertion_json"))
	}

	if hasTOTP {
		secret, err := decryptLoginTOTP(r.AuthKey, row.EncryptedSecret)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, errors.New("totp secret corrupted"))
		}
		defer secret.Destroy()
		if err := auth.ValidateTOTPCodeBytes(secret.Bytes(), []byte(r.TotpCode)); err != nil {
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid totp code"))
		}
	} else {
		if s.wa == nil {
			return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("webauthn not configured"))
		}
		if err := s.consumeWebAuthnAssertion(ctx, tx, uc.UserID, r.MfaSessionId, r.WebauthnAssertionJson); err != nil {
			return nil, err
		}
	}

	if err := repo_user_login_totp.New(tx).DeleteUserLoginTOTP(ctx, uc.UserID); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	middleware.SetAuditTarget(ctx, uc.UserID)
	return connect.NewResponse(&pb.LoginTOTPServiceDisableResponse{}), nil
}

// Status reports the configured / enabled flags for the caller.
func (s *Service) Status(ctx context.Context, _ *connect.Request[pb.LoginTOTPServiceStatusRequest]) (*connect.Response[pb.LoginTOTPServiceStatusResponse], error) {
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)

	row, err := repo_user_login_totp.New(tx).GetUserLoginTOTP(ctx, uc.UserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return connect.NewResponse(&pb.LoginTOTPServiceStatusResponse{}), nil
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&pb.LoginTOTPServiceStatusResponse{
		Configured: true,
		Enabled:    row.Enabled,
	}), nil
}

// --- helpers ---

func (s *Service) verifyAuthKey(ctx context.Context, tx pgx.Tx, uc *middleware.UserContext, authKey []byte) error {
	if len(authKey) == 0 {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("auth_key required"))
	}
	// Reach for the user_auth row through the RLS-scoped tx so the
	// challenge is double-checked against the authenticated session.
	var hash string
	err := tx.QueryRow(ctx, `SELECT auth_key_hash FROM user_auth WHERE user_id = $1`, uc.UserID).Scan(&hash)
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	ok, err := auth.VerifyAuthKey(authKey, hash)
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	if !ok {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("auth_key mismatch"))
	}
	return nil
}

// decryptLoginTOTP returns the plaintext base32 secret inside a
// memguard.LockedBuffer. The intermediate K_login_totp material is wiped
// before this function returns; the returned buffer holds the only live
// copy of the plaintext, so callers MUST `Destroy()` it as soon as
// validation completes (typically via defer at the call site).
func decryptLoginTOTP(authKey []byte, blob []byte) (*memguard.LockedBuffer, error) {
	return auth.OpenLoginTOTPSecret(authKey, blob)
}

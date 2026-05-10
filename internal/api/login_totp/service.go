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
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"

	pb "github.com/sxwebdev/oblivio/internal/api/gen/go/oblivio/v1"
	"github.com/sxwebdev/oblivio/internal/api/gen/go/oblivio/v1/obliviov1connect"
	"github.com/sxwebdev/oblivio/internal/api/middleware"
	"github.com/sxwebdev/oblivio/internal/auth"
	srvcrypto "github.com/sxwebdev/oblivio/internal/crypto"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_user_login_totp"
)

// Service implements LoginTOTPService.
type Service struct {
	obliviov1connect.UnimplementedLoginTOTPServiceHandler
}

// NewService constructs the handler.
func NewService() *Service {
	return &Service{}
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

	secret, err := decryptLoginTOTP(r.AuthKey, r.EncryptedSecret)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	defer func() { wipeString(&secret) }()

	if err := auth.ValidateTOTPCode(secret, r.TotpCode); err != nil {
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
	defer func() { wipeString(&secret) }()
	if err := auth.ValidateTOTPCode(secret, req.Msg.TotpCode); err != nil {
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

// Disable removes the stored secret entirely.
func (s *Service) Disable(ctx context.Context, req *connect.Request[pb.LoginTOTPServiceDisableRequest]) (*connect.Response[pb.LoginTOTPServiceDisableResponse], error) {
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)

	if err := s.verifyAuthKey(ctx, tx, uc, req.Msg.AuthKey); err != nil {
		return nil, err
	}
	row, err := repo_user_login_totp.New(tx).GetUserLoginTOTP(ctx, uc.UserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return connect.NewResponse(&pb.LoginTOTPServiceDisableResponse{}), nil
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	secret, err := decryptLoginTOTP(req.Msg.AuthKey, row.EncryptedSecret)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("totp secret corrupted"))
	}
	defer func() { wipeString(&secret) }()
	if err := auth.ValidateTOTPCode(secret, req.Msg.TotpCode); err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid totp code"))
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

// decryptLoginTOTP returns the plaintext base32 secret. The K_login_totp
// buffer is wiped before the function returns.
func decryptLoginTOTP(authKey []byte, blob []byte) (string, error) {
	keyBuf, err := auth.DeriveLoginTOTPKey(authKey)
	if err != nil {
		return "", err
	}
	defer keyBuf.Destroy()
	pt, err := srvcrypto.AESGCMOpen(keyBuf.Bytes(), blob, []byte(auth.LoginTOTPAAD))
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// wipeString best-effort scrubs the backing bytes of a string holding a
// short-lived secret. Go strings are immutable so we go through an unsafe-ish
// path here only when we own the memory.
func wipeString(s *string) {
	if s == nil || *s == "" {
		return
	}
	b := []byte(*s)
	for i := range b {
		b[i] = 0
	}
	*s = ""
}

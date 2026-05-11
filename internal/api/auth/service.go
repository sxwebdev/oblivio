// Package auth implements the ConnectRPC AuthService handler.
package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/sxwebdev/oblivio/internal/api/gen/go/oblivio/v1"
	"github.com/sxwebdev/oblivio/internal/api/gen/go/oblivio/v1/obliviov1connect"
	"github.com/sxwebdev/oblivio/internal/api/middleware"
	"github.com/sxwebdev/oblivio/internal/audit"
	"github.com/sxwebdev/oblivio/internal/auth"
	"github.com/sxwebdev/oblivio/internal/config"
	"github.com/sxwebdev/oblivio/internal/email"
	"github.com/sxwebdev/oblivio/internal/metrics"
	"github.com/sxwebdev/oblivio/internal/models"
	"github.com/sxwebdev/oblivio/internal/store"
	"github.com/sxwebdev/oblivio/internal/store/repos"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_auth_sessions"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_email_verification_tokens"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_user_auth"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_user_kdf_params"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_user_vault"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_user_webauthn_credentials"
)

// Service implements the AuthService ConnectRPC contract.
type Service struct {
	obliviov1connect.UnimplementedAuthServiceHandler

	st                *store.Store
	am                *auth.Manager
	argon2            auth.Argon2Params
	auditWriter       *audit.Writer
	defaultDeviceType string
	wa                *wa.WebAuthn
	mfa               *auth.MFAStore
	recovery          *auth.RecoveryStore
	emailer           email.Sender
	publicURL         string
	appName           string
}

// Deps bundles the dependencies required to build the AuthService handler.
type Deps struct {
	Store         *store.Store
	AuthManager   *auth.Manager
	Cfg           config.AuthConfig
	AuditWriter   *audit.Writer
	WebAuthn      *wa.WebAuthn
	MFAStore      *auth.MFAStore
	RecoveryStore *auth.RecoveryStore
	Email         email.Sender
	PublicURL     string
	AppName       string
}

// NewService constructs the AuthService handler. AuthService procedures are
// on the anonymous allowlist so the audit-chain interceptor (which keys off
// the authenticated user_id) never runs against them — the handler must
// therefore log explicitly after the action succeeds.
func NewService(d Deps) *Service {
	return &Service{
		st: d.Store,
		am: d.AuthManager,
		argon2: auth.Argon2Params{
			T:    d.Cfg.Argon2Server.T,
			MKiB: d.Cfg.Argon2Server.MKiB,
			P:    d.Cfg.Argon2Server.P,
		},
		auditWriter:       d.AuditWriter,
		defaultDeviceType: "web",
		wa:                d.WebAuthn,
		mfa:               d.MFAStore,
		recovery:          d.RecoveryStore,
		emailer:           d.Email,
		publicURL:         d.PublicURL,
		appName:           d.AppName,
	}
}

func (s *Service) logAudit(ctx context.Context, userID uuid.UUID, action models.AuditAction, req connect.AnyRequest, extra map[string]any) {
	if s.auditWriter == nil {
		return
	}
	meta := map[string]any{
		"procedure": req.Spec().Procedure,
	}
	maps.Copy(meta, extra)
	ev := audit.Event{
		Action:    action,
		UserAgent: req.Header().Get("User-Agent"),
		Metadata:  meta,
	}
	if userID != uuid.Nil {
		ev.UserID = uuid.NullUUID{UUID: userID, Valid: true}
		ev.TargetID = uuid.NullUUID{UUID: userID, Valid: true}
	}
	s.auditWriter.AppendOrLog(ctx, ev)
}

// Register provisions a new user from the client-supplied artefacts.
func (s *Service) Register(ctx context.Context, req *connect.Request[pb.RegisterRequest]) (*connect.Response[pb.RegisterResponse], error) {
	r := req.Msg
	if err := validateRegister(r); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	hashed, err := auth.HashAuthKey(r.AuthKey, s.argon2)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	recoveryProofHash, err := auth.HashAuthKey(r.RecoveryProof, s.argon2)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	pool := s.st.Pool()
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	users := s.st.Users().WithTx(tx)
	kdf := s.st.UserKDFParams().WithTx(tx)
	ua := s.st.UserAuth().WithTx(tx)
	uv := s.st.UserVault().WithTx(tx)

	newUser, err := users.CreateUser(ctx, strings.ToLower(r.Email))
	if err != nil {
		if isUniqueViolation(err) {
			return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("email already registered"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	if err := kdf.UpsertUserKDFParams(ctx, repo_user_kdf_params.UpsertUserKDFParamsParams{
		UserID:     newUser.ID,
		SaltUser:   r.SaltUser,
		Argon2T:    int32(r.KdfParams.GetT()),
		Argon2MKib: int32(r.KdfParams.GetMKib()),
		Argon2P:    int32(r.KdfParams.GetP()),
		Algo:       firstNonEmpty(r.KdfParams.GetAlgo(), "argon2id"),
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	if err := ua.UpsertUserAuth(ctx, repo_user_auth.UpsertUserAuthParams{
		UserID:      newUser.ID,
		AuthKeyHash: hashed,
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	if err := uv.CreateUserVault(ctx, repo_user_vault.CreateUserVaultParams{
		UserID:                  newUser.ID,
		Verifier:                r.Verifier,
		WrappedVaultKey:         r.WrappedVaultKey,
		RecoverySalt:            r.RecoverySalt,
		RecoveryWrappedVaultKey: r.RecoveryWrappedVaultKey,
		RecoveryProofHash:       recoveryProofHash,
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	tokens, err := s.am.Issue(ctx, newUser.ID, deviceID(r.DeviceInfo), deviceType(r.DeviceInfo, s.defaultDeviceType), deviceName(r.DeviceInfo))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	// Fire-and-log the verification email. Failure is non-fatal: the user
	// is registered, can use the app, and can request a resend later. The
	// emailer is a NoopSender when the operator left provider="" in config.
	if err := s.sendVerificationEmail(ctx, newUser.ID, newUser.Email); err != nil {
		s.logAudit(ctx, newUser.ID, models.AuditActionRegister, req, map[string]any{
			"device_id":     deviceID(r.DeviceInfo),
			"email_warning": err.Error(),
		})
	} else {
		s.logAudit(ctx, newUser.ID, models.AuditActionRegister, req, map[string]any{
			"device_id": deviceID(r.DeviceInfo),
		})
	}

	return connect.NewResponse(&pb.RegisterResponse{
		UserId: newUser.ID.String(),
		AuthPayload: buildAuthPayload(tokens, &payloadKeys{
			Verifier:        r.Verifier,
			WrappedVaultKey: r.WrappedVaultKey,
			VaultKeyVersion: 1,
		}),
	}), nil
}

// GetKDFParams returns the per-user Argon2id parameters needed by the client
// to re-derive master_key from master_password.
func (s *Service) GetKDFParams(ctx context.Context, req *connect.Request[pb.GetKDFParamsRequest]) (*connect.Response[pb.GetKDFParamsResponse], error) {
	email := strings.ToLower(strings.TrimSpace(req.Msg.Email))
	if email == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("email required"))
	}

	u, err := s.st.Users().GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return connect.NewResponse(&pb.GetKDFParamsResponse{
				SaltUser:  pseudoSalt(email),
				KdfParams: defaultKDFParams(),
			}), nil
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	params, err := s.st.UserKDFParams().GetUserKDFParams(ctx, u.ID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&pb.GetKDFParamsResponse{
		SaltUser: params.SaltUser,
		KdfParams: &pb.Argon2Params{
			T:    uint32(params.Argon2T),
			MKib: uint32(params.Argon2MKib),
			P:    uint32(params.Argon2P),
			Algo: params.Algo,
		},
	}), nil
}

// Authorize verifies auth_key. When 2FA is configured, it returns an
// MFAChallenge that the client completes via CompleteMFA. Otherwise it
// issues tokens straight away.
func (s *Service) Authorize(ctx context.Context, req *connect.Request[pb.AuthorizeRequest]) (*connect.Response[pb.AuthorizeResponse], error) {
	r := req.Msg
	email := strings.ToLower(strings.TrimSpace(r.Email))
	if email == "" || len(r.AuthKey) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("email and auth_key required"))
	}

	u, err := s.st.Users().GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Anti-enumeration: hash a dummy auth_key against the canned
			// dummy hash so the wall-clock cost matches a real verify.
			// Without this an attacker can distinguish "user exists" from
			// "user doesn't" by timing.
			_, _ = auth.VerifyAuthKey(r.AuthKey, dummyAuthHash())
			metrics.LoginAttemptsTotal.WithLabelValues("failure").Inc()
			return nil, unauthenticated()
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	ua, err := s.st.UserAuth().GetUserAuth(ctx, u.ID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	// Lockout: refuse before doing the expensive Argon2 verify.
	if ua.LockedUntil.Valid && ua.LockedUntil.Time.After(time.Now()) {
		metrics.LoginAttemptsTotal.WithLabelValues("locked").Inc()
		return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("account temporarily locked, try again later"))
	}

	ok, err := auth.VerifyAuthKey(r.AuthKey, ua.AuthKeyHash)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if !ok {
		// RecordFailedLogin increments and locks at the threshold (5 → 15min).
		_, _ = s.st.UserAuth().RecordFailedLogin(ctx, u.ID)
		metrics.LoginAttemptsTotal.WithLabelValues("failure").Inc()
		return nil, unauthenticated()
	}
	// Reset the counter on a clean credentials check — even though we may
	// still gate on MFA below, a successful auth_key proves possession of
	// the password and is what brute-force protection cares about.
	_ = s.st.UserAuth().ResetFailedLogin(ctx, u.ID)

	// Check 2FA state. Either TOTP enabled or registered passkeys triggers
	// an MFA challenge.
	totpRow, totpErr := s.st.UserLoginTOTP().GetUserLoginTOTP(ctx, u.ID)
	totpEnabled := totpErr == nil && totpRow != nil && totpRow.Enabled

	credCount := int64(0)
	if s.wa != nil {
		// user_webauthn_credentials is RLS-protected — bypass tx because
		// Authorize is anonymous (no per-user GUC set by middleware).
		_ = s.st.SystemDo(ctx, func(tx pgx.Tx) error {
			c, err := s.st.UserWebAuthn(repos.WithTx(tx)).CountWebAuthnCredentials(ctx, u.ID)
			if err == nil {
				credCount = c
			}
			return nil
		})
	}

	if totpEnabled || credCount > 0 {
		ch := auth.MFAChallenge{
			UserID:       u.ID,
			Email:        u.Email,
			AuthKey:      append([]byte(nil), r.AuthKey...),
			DeviceID:     deviceID(r.DeviceInfo),
			DeviceType:   deviceType(r.DeviceInfo, s.defaultDeviceType),
			DeviceName:   deviceName(r.DeviceInfo),
			TOTPRequired: totpEnabled,
		}
		mfaResp := &pb.MFAChallenge{
			TotpRequired:     totpEnabled,
			WebauthnRequired: credCount > 0,
		}
		if credCount > 0 {
			var creds []*models.UserWebauthnCredential
			if err := s.st.SystemDo(ctx, func(tx pgx.Tx) error {
				c, err := s.st.UserWebAuthn(repos.WithTx(tx)).ListWebAuthnCredentials(ctx, u.ID)
				if err != nil {
					return err
				}
				creds = c
				return nil
			}); err != nil {
				return nil, connect.NewError(connect.CodeInternal, err)
			}
			wuser := buildWebAuthnUser(u, creds)
			options, session, err := s.wa.BeginLogin(wuser)
			if err != nil {
				return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("webauthn begin login: %w", err))
			}
			ch.WebAuthnState = session
			optJSON, err := json.Marshal(options)
			if err != nil {
				return nil, connect.NewError(connect.CodeInternal, err)
			}
			mfaResp.WebauthnOptionsJson = optJSON
		}
		sid := s.mfa.Put(ch)
		mfaResp.SessionId = sid.String()
		metrics.LoginAttemptsTotal.WithLabelValues("mfa_challenge").Inc()
		return connect.NewResponse(&pb.AuthorizeResponse{MfaChallenge: mfaResp}), nil
	}

	return s.issueAuthorized(ctx, req, u.ID, deviceID(r.DeviceInfo), deviceType(r.DeviceInfo, s.defaultDeviceType), deviceName(r.DeviceInfo))
}

// CompleteMFA finalises the authentication after the user satisfies the
// requested factor. Exactly one of totp_code / webauthn_assertion_json must
// be provided.
func (s *Service) CompleteMFA(ctx context.Context, req *connect.Request[pb.CompleteMFARequest]) (*connect.Response[pb.CompleteMFAResponse], error) {
	r := req.Msg
	id, err := uuid.Parse(r.SessionId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid session_id"))
	}

	hasTOTP := strings.TrimSpace(r.TotpCode) != ""
	hasWA := len(r.WebauthnAssertionJson) > 0
	if hasTOTP == hasWA {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("exactly one of totp_code or webauthn_assertion_json required"))
	}

	ch, err := s.mfa.Peek(id)
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("mfa challenge expired"))
	}

	switch {
	case hasTOTP:
		if !ch.TOTPRequired {
			return nil, connect.NewError(connect.CodePermissionDenied, errors.New("totp not configured for this challenge"))
		}
		row, err := s.st.UserLoginTOTP().GetUserLoginTOTP(ctx, ch.UserID)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		secret, err := openLoginTOTP(ch.AuthKey, row.EncryptedSecret)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		if err := auth.ValidateTOTPCode(secret, r.TotpCode); err != nil {
			metrics.MFAAttemptsTotal.WithLabelValues("totp", "failure").Inc()
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid totp code"))
		}
		metrics.MFAAttemptsTotal.WithLabelValues("totp", "success").Inc()
	case hasWA:
		if s.wa == nil || ch.WebAuthnState == nil {
			return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("webauthn challenge not present"))
		}
		var creds []*models.UserWebauthnCredential
		var u *models.User
		if err := s.st.SystemDo(ctx, func(tx pgx.Tx) error {
			c, err := s.st.UserWebAuthn(repos.WithTx(tx)).ListWebAuthnCredentials(ctx, ch.UserID)
			if err != nil {
				return err
			}
			creds = c
			usr, err := s.st.Users(repos.WithTx(tx)).GetUserByID(ctx, ch.UserID)
			if err != nil {
				return err
			}
			u = usr
			return nil
		}); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		wuser := buildWebAuthnUser(u, creds)
		parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(r.WebauthnAssertionJson))
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("parse assertion: %w", err))
		}
		credential, err := s.wa.ValidateLogin(wuser, *ch.WebAuthnState, parsed)
		if err != nil {
			metrics.MFAAttemptsTotal.WithLabelValues("webauthn", "failure").Inc()
			return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("webauthn validate: %w", err))
		}
		metrics.MFAAttemptsTotal.WithLabelValues("webauthn", "success").Inc()
		// Update sign_count for the touched credential.
		_ = s.st.SystemDo(ctx, func(tx pgx.Tx) error {
			matched, err := s.st.UserWebAuthn(repos.WithTx(tx)).GetWebAuthnCredentialByCredID(ctx, credential.ID)
			if err != nil {
				return nil
			}
			return s.st.UserWebAuthn(repos.WithTx(tx)).TouchWebAuthnCredential(ctx, repo_user_webauthn_credentials.TouchWebAuthnCredentialParams{
				ID:        matched.ID,
				SignCount: int64(credential.Authenticator.SignCount),
			})
		})
	}

	// Consume the challenge only after successful validation.
	taken, err := s.mfa.Take(id)
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("mfa challenge expired"))
	}
	// AuthKey is no longer needed; scrub before the GC sees the slice.
	defer taken.Wipe()
	defer ch.Wipe()

	dev := r.DeviceInfo
	devID := ch.DeviceID
	devType := ch.DeviceType
	devName := ch.DeviceName
	if dev != nil {
		if dev.DeviceId != "" {
			devID = dev.DeviceId
		}
		if dev.DeviceType != "" {
			devType = dev.DeviceType
		}
		if dev.DeviceName != "" {
			devName = dev.DeviceName
		}
	}

	resp, err := s.issueAuthorized(ctx, req, ch.UserID, devID, devType, devName)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&pb.CompleteMFAResponse{AuthPayload: resp.Msg.AuthPayload}), nil
}

// issueAuthorized loads vault artefacts, mints tokens and writes the login
// audit event. Shared between Authorize (no 2FA) and CompleteMFA.
func (s *Service) issueAuthorized(ctx context.Context, req connect.AnyRequest, userID uuid.UUID, devID, devType, devName string) (*connect.Response[pb.AuthorizeResponse], error) {
	uv, err := s.st.UserVault().GetUserVault(ctx, userID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	tokens, err := s.am.Issue(ctx, userID, devID, devType, devName)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	s.logAudit(ctx, userID, models.AuditActionLogin, req, map[string]any{
		"device_id": devID,
	})
	metrics.LoginAttemptsTotal.WithLabelValues("success").Inc()
	return connect.NewResponse(&pb.AuthorizeResponse{
		AuthPayload: buildAuthPayload(tokens, &payloadKeys{
			Verifier:        uv.Verifier,
			WrappedVaultKey: uv.WrappedVaultKey,
			VaultKeyVersion: uint32(uv.VaultKeyVersion),
		}),
	}), nil
}

// RefreshToken rotates a refresh token, returning a new pair.
func (s *Service) RefreshToken(ctx context.Context, req *connect.Request[pb.RefreshTokenRequest]) (*connect.Response[pb.RefreshTokenResponse], error) {
	r := req.Msg
	if r.RefreshToken == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("refresh_token required"))
	}
	tokens, err := s.am.Refresh(ctx, r.RefreshToken, deviceType(r.DeviceInfo, s.defaultDeviceType), deviceName(r.DeviceInfo))
	if err != nil {
		metrics.RefreshAttemptsTotal.WithLabelValues("failure").Inc()
		return nil, unauthenticated()
	}

	uv, err := s.st.UserVault().GetUserVault(ctx, tokens.UserID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	s.logAudit(ctx, tokens.UserID, models.AuditActionRefresh, req, nil)
	metrics.RefreshAttemptsTotal.WithLabelValues("success").Inc()

	return connect.NewResponse(&pb.RefreshTokenResponse{
		AuthPayload: buildAuthPayload(tokens, &payloadKeys{
			Verifier:        uv.Verifier,
			WrappedVaultKey: uv.WrappedVaultKey,
			VaultKeyVersion: uint32(uv.VaultKeyVersion),
		}),
	}), nil
}

// --- Email verification (plan §5.1) -----------------------------------

const (
	emailVerifyPurpose = "verify_email"
	emailVerifyTTL     = 24 * time.Hour
)

// sendVerificationEmail mints a fresh token, persists its SHA-256 hash and
// dispatches the verification message. Skips when no Sender is configured
// or when the user has no email (shouldn't happen but defence-in-depth).
func (s *Service) sendVerificationEmail(ctx context.Context, userID uuid.UUID, addr string) error {
	if s.emailer == nil || addr == "" || s.publicURL == "" {
		return nil
	}
	if _, ok := s.emailer.(*email.NoopSender); ok {
		return nil
	}
	token, err := newVerificationToken()
	if err != nil {
		return err
	}
	hash := sha256Sum([]byte(token))
	if err := s.st.EmailVerificationTokens().InsertEmailVerificationToken(ctx, repo_email_verification_tokens.InsertEmailVerificationTokenParams{
		TokenHash: hash,
		UserID:    userID,
		Purpose:   emailVerifyPurpose,
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(emailVerifyTTL), Valid: true},
	}); err != nil {
		return fmt.Errorf("insert verify token: %w", err)
	}
	link := strings.TrimRight(s.publicURL, "/") + "/verify-email?token=" + token
	subj, text, html, err := email.RenderVerifyEmail(email.VerifyEmailParams{VerifyURL: link, AppName: s.appName})
	if err != nil {
		return err
	}
	return s.emailer.Send(ctx, email.Message{To: addr, Subject: subj, TextBody: text, HTMLBody: html})
}

// VerifyEmail consumes a verification token and stamps users.email_verified_at.
func (s *Service) VerifyEmail(ctx context.Context, req *connect.Request[pb.VerifyEmailRequest]) (*connect.Response[pb.VerifyEmailResponse], error) {
	tok := strings.TrimSpace(req.Msg.Token)
	if tok == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("token required"))
	}
	hash := sha256Sum([]byte(tok))
	uid, err := s.st.EmailVerificationTokens().ConsumeEmailVerificationToken(ctx, hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("token invalid or expired"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := s.st.Users().MarkEmailVerified(ctx, uid); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	s.logAudit(ctx, uid, models.AuditActionEmailVerify, req, nil)
	return connect.NewResponse(&pb.VerifyEmailResponse{}), nil
}

// ResendVerification invalidates outstanding tokens and emails a new one.
// The response is intentionally generic so an attacker can't probe for
// registered emails — we always return success.
func (s *Service) ResendVerification(ctx context.Context, req *connect.Request[pb.ResendVerificationRequest]) (*connect.Response[pb.ResendVerificationResponse], error) {
	addr := strings.ToLower(strings.TrimSpace(req.Msg.Email))
	if addr == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("email required"))
	}
	u, err := s.st.Users().GetUserByEmail(ctx, addr)
	if err != nil {
		// Quiet success on unknown email (anti-enumeration).
		if errors.Is(err, pgx.ErrNoRows) {
			return connect.NewResponse(&pb.ResendVerificationResponse{}), nil
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if u.EmailVerifiedAt.Valid {
		// Already verified; no point sending another link. Generic OK.
		return connect.NewResponse(&pb.ResendVerificationResponse{}), nil
	}
	_, _ = s.st.EmailVerificationTokens().InvalidateActiveEmailVerificationTokens(ctx,
		repo_email_verification_tokens.InvalidateActiveEmailVerificationTokensParams{
			UserID:  u.ID,
			Purpose: emailVerifyPurpose,
		})
	if err := s.sendVerificationEmail(ctx, u.ID, u.Email); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	s.logAudit(ctx, u.ID, models.AuditActionEmailResend, req, nil)
	return connect.NewResponse(&pb.ResendVerificationResponse{}), nil
}

// newVerificationToken returns a 32-byte URL-safe base64 token.
func newVerificationToken() (string, error) {
	b := make([]byte, 32)
	if _, err := readRandom(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// ChangeMasterPassword rotates the user's KDF + verifier + wrapped_vault_key
// under a freshly chosen master_password. Records and item ciphertexts are
// untouched — only the wrapper around vault_key changes. All sessions
// EXCEPT the calling one are revoked so a stolen password can't outlive
// the rotation.
func (s *Service) ChangeMasterPassword(ctx context.Context, req *connect.Request[pb.ChangeMasterPasswordRequest]) (*connect.Response[pb.ChangeMasterPasswordResponse], error) {
	uc, ok := middleware.FromContext(ctx)
	if !ok {
		return nil, unauthenticated()
	}
	r := req.Msg
	if len(r.OldAuthKey) < 16 || len(r.NewAuthKey) < 16 || len(r.NewSaltUser) < 16 ||
		r.NewKdfParams == nil || len(r.NewVerifier) == 0 || len(r.NewWrappedVaultKey) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("missing change-password artefacts"))
	}

	ua, err := s.st.UserAuth().GetUserAuth(ctx, uc.UserID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	ok2, err := auth.VerifyAuthKey(r.OldAuthKey, ua.AuthKeyHash)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if !ok2 {
		// Treat a wrong old-password the same as a failed login: increment
		// the lockout counter and return Unauthenticated.
		_, _ = s.st.UserAuth().RecordFailedLogin(ctx, uc.UserID)
		return nil, unauthenticated()
	}

	hashed, err := auth.HashAuthKey(r.NewAuthKey, s.argon2)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	// Rotate everything in a single transaction. SystemDo sets the bypass
	// GUC so the auth_sessions revoke at the end satisfies RLS.
	if err := s.st.SystemDo(ctx, func(tx pgx.Tx) error {
		if err := s.st.UserKDFParams(repos.WithTx(tx)).UpsertUserKDFParams(ctx, repo_user_kdf_params.UpsertUserKDFParamsParams{
			UserID:     uc.UserID,
			SaltUser:   r.NewSaltUser,
			Argon2T:    int32(r.NewKdfParams.GetT()),
			Argon2MKib: int32(r.NewKdfParams.GetMKib()),
			Argon2P:    int32(r.NewKdfParams.GetP()),
			Algo:       firstNonEmpty(r.NewKdfParams.GetAlgo(), "argon2id"),
		}); err != nil {
			return err
		}
		if err := s.st.UserAuth(repos.WithTx(tx)).UpsertUserAuth(ctx, repo_user_auth.UpsertUserAuthParams{
			UserID:      uc.UserID,
			AuthKeyHash: hashed,
		}); err != nil {
			return err
		}
		return s.st.UserVault(repos.WithTx(tx)).UpdateUserVaultPassword(ctx, repo_user_vault.UpdateUserVaultPasswordParams{
			UserID:          uc.UserID,
			Verifier:        r.NewVerifier,
			WrappedVaultKey: r.NewWrappedVaultKey,
		})
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	// Revoke other sessions both at the DB level (auth_sessions row) and
	// the token level (auth_tokens). The current session survives so the
	// user keeps the tab they just typed the new password in.
	if err := s.st.SystemDo(ctx, func(tx pgx.Tx) error {
		_, err := s.st.AuthSessions(repos.WithTx(tx)).RevokeAllUserSessionsExcept(ctx, repo_auth_sessions.RevokeAllUserSessionsExceptParams{
			UserID: uc.UserID,
			ID:     uc.SessionID,
		})
		return err
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := s.am.RevokeUserTokensExceptSession(ctx, uc.UserID, uc.SessionID); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	s.logAudit(ctx, uc.UserID, models.AuditActionPasswordChange, req, map[string]any{
		"device_id": uc.DeviceID,
	})
	return connect.NewResponse(&pb.ChangeMasterPasswordResponse{}), nil
}

// Logout invalidates the caller's access token and the corresponding session row.
func (s *Service) Logout(ctx context.Context, req *connect.Request[pb.LogoutRequest]) (*connect.Response[pb.LogoutResponse], error) {
	uc, ok := middleware.FromContext(ctx)
	if !ok {
		return nil, unauthenticated()
	}
	if err := s.am.Logout(ctx, uc.AccessToken); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	s.logAudit(ctx, uc.UserID, models.AuditActionLogout, req, map[string]any{
		"device_id": uc.DeviceID,
	})
	return connect.NewResponse(&pb.LogoutResponse{}), nil
}

// GetMyKeys returns the encrypted vault artefacts the client needs to unlock
// its key tree.
func (s *Service) GetMyKeys(ctx context.Context, _ *connect.Request[pb.GetMyKeysRequest]) (*connect.Response[pb.GetMyKeysResponse], error) {
	uc, ok := middleware.FromContext(ctx)
	if !ok {
		return nil, unauthenticated()
	}
	uv, err := s.st.UserVault().GetUserVault(ctx, uc.UserID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&pb.GetMyKeysResponse{
		Verifier:        uv.Verifier,
		WrappedVaultKey: uv.WrappedVaultKey,
		VaultKeyVersion: uint32(uv.VaultKeyVersion),
	}), nil
}

// --- Recovery (plan §5.5) ---------------------------------------------

// GetRecoveryParams returns the recovery salt + KDF params so the client can
// re-derive recovery_key from the recovery_code.
func (s *Service) GetRecoveryParams(ctx context.Context, req *connect.Request[pb.GetRecoveryParamsRequest]) (*connect.Response[pb.GetRecoveryParamsResponse], error) {
	email := strings.ToLower(strings.TrimSpace(req.Msg.Email))
	if email == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("email required"))
	}
	u, err := s.st.Users().GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Anti-enumeration. Return stable pseudo-params; the client
			// will compute a proof and RecoveryStart will fail uniformly.
			return connect.NewResponse(&pb.GetRecoveryParamsResponse{
				RecoverySalt: pseudoSalt(email),
				KdfParams:    defaultKDFParams(),
			}), nil
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	uv, err := s.st.UserVault().GetUserVault(ctx, u.ID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	params, err := s.st.UserKDFParams().GetUserKDFParams(ctx, u.ID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&pb.GetRecoveryParamsResponse{
		RecoverySalt: uv.RecoverySalt,
		KdfParams: &pb.Argon2Params{
			T:    uint32(params.Argon2T),
			MKib: uint32(params.Argon2MKib),
			P:    uint32(params.Argon2P),
			Algo: params.Algo,
		},
	}), nil
}

// RecoveryStart verifies recovery_proof and, on success, returns the
// recovery-wrapped vault_key so the client can decrypt it locally.
func (s *Service) RecoveryStart(ctx context.Context, req *connect.Request[pb.RecoveryStartRequest]) (*connect.Response[pb.RecoveryStartResponse], error) {
	email := strings.ToLower(strings.TrimSpace(req.Msg.Email))
	if email == "" || len(req.Msg.RecoveryProof) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("email and recovery_proof required"))
	}
	u, err := s.st.Users().GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Anti-enumeration: pad timing with a dummy verify so the
			// "no such email" branch matches the real path.
			_, _ = auth.VerifyAuthKey(req.Msg.RecoveryProof, dummyAuthHash())
			return nil, unauthenticated()
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	uv, err := s.st.UserVault().GetUserVault(ctx, u.ID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	ok, err := auth.VerifyAuthKey(req.Msg.RecoveryProof, uv.RecoveryProofHash)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if !ok {
		return nil, unauthenticated()
	}
	sid := s.recovery.Put(auth.RecoverySession{
		UserID: u.ID,
		Email:  u.Email,
	})
	s.logAudit(ctx, u.ID, models.AuditActionRecoveryStart, req, nil)
	return connect.NewResponse(&pb.RecoveryStartResponse{
		RecoverySessionId:       sid.String(),
		RecoveryWrappedVaultKey: uv.RecoveryWrappedVaultKey,
	}), nil
}

// RecoveryComplete rotates the user's auth artefacts to a freshly-derived
// master_password. All sessions are revoked.
func (s *Service) RecoveryComplete(ctx context.Context, req *connect.Request[pb.RecoveryCompleteRequest]) (*connect.Response[pb.RecoveryCompleteResponse], error) {
	r := req.Msg
	id, err := uuid.Parse(r.RecoverySessionId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid recovery_session_id"))
	}
	if len(r.SaltUser) < 16 || len(r.AuthKey) < 16 || r.KdfParams == nil ||
		len(r.Verifier) == 0 || len(r.WrappedVaultKey) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("missing new auth artefacts"))
	}
	sess, err := s.recovery.Take(id)
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("recovery session expired"))
	}

	hashed, err := auth.HashAuthKey(r.AuthKey, s.argon2)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	if err := s.st.SystemDo(ctx, func(tx pgx.Tx) error {
		// One transaction: rotate KDF/auth/vault, revoke all sessions.
		// SystemDo sets app.bypass_rls so the auth_sessions write satisfies RLS.
		if err := s.st.UserKDFParams(repos.WithTx(tx)).UpsertUserKDFParams(ctx, repo_user_kdf_params.UpsertUserKDFParamsParams{
			UserID:     sess.UserID,
			SaltUser:   r.SaltUser,
			Argon2T:    int32(r.KdfParams.GetT()),
			Argon2MKib: int32(r.KdfParams.GetMKib()),
			Argon2P:    int32(r.KdfParams.GetP()),
			Algo:       firstNonEmpty(r.KdfParams.GetAlgo(), "argon2id"),
		}); err != nil {
			return err
		}
		if err := s.st.UserAuth(repos.WithTx(tx)).UpsertUserAuth(ctx, repo_user_auth.UpsertUserAuthParams{
			UserID:      sess.UserID,
			AuthKeyHash: hashed,
		}); err != nil {
			return err
		}
		if err := s.st.UserVault(repos.WithTx(tx)).CompleteRecovery(ctx, repo_user_vault.CompleteRecoveryParams{
			UserID:          sess.UserID,
			Verifier:        r.Verifier,
			WrappedVaultKey: r.WrappedVaultKey,
		}); err != nil {
			return err
		}
		return s.st.AuthSessions(repos.WithTx(tx)).RevokeAllUserSessions(ctx, sess.UserID)
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	// Burn every JWT we ever signed for this user from the in-memory
	// tokenmanager store. Without this an access token snapped at recovery
	// time would stay valid for its full 20 min TTL — defeating the point
	// of password rotation.
	if err := s.am.RevokeAllUserTokens(ctx, sess.UserID); err != nil {
		// Non-fatal: DB-side revocation already happened. Still log so the
		// audit chain captures the partial state.
		s.logAudit(ctx, sess.UserID, models.AuditActionRecoveryComplete, req, map[string]any{
			"warning": "in-memory token revocation failed: " + err.Error(),
		})
		return connect.NewResponse(&pb.RecoveryCompleteResponse{}), nil
	}

	s.logAudit(ctx, sess.UserID, models.AuditActionRecoveryComplete, req, nil)

	return connect.NewResponse(&pb.RecoveryCompleteResponse{}), nil
}

// --- helpers ---

type payloadKeys struct {
	Verifier        []byte
	WrappedVaultKey []byte
	VaultKeyVersion uint32
}

func buildAuthPayload(t auth.IssuedTokens, k *payloadKeys) *pb.AuthPayload {
	p := &pb.AuthPayload{
		AccessToken:      t.AccessToken,
		RefreshToken:     t.RefreshToken,
		AccessExpiresAt:  timestamppb.New(t.AccessExpiresAt),
		RefreshExpiresAt: timestamppb.New(t.RefreshExpiresAt),
		DeviceId:         t.DeviceID,
	}
	if k != nil {
		p.Verifier = k.Verifier
		p.WrappedVaultKey = k.WrappedVaultKey
		p.VaultKeyVersion = k.VaultKeyVersion
	}
	return p
}

func validateRegister(r *pb.RegisterRequest) error {
	if r.Email == "" || !strings.Contains(r.Email, "@") {
		return errors.New("invalid email")
	}
	if len(r.SaltUser) < 16 || len(r.AuthKey) < 16 {
		return errors.New("invalid kdf material")
	}
	if r.KdfParams == nil {
		return errors.New("kdf_params required")
	}
	if len(r.Verifier) == 0 || len(r.WrappedVaultKey) == 0 {
		return errors.New("verifier and wrapped_vault_key required")
	}
	if len(r.RecoverySalt) < 16 || len(r.RecoveryWrappedVaultKey) == 0 || len(r.RecoveryProof) == 0 {
		return errors.New("recovery artefacts required")
	}
	if r.DeviceInfo == nil || r.DeviceInfo.DeviceId == "" {
		return errors.New("device_info.device_id required")
	}
	return nil
}

func unauthenticated() error {
	return connect.NewError(connect.CodeUnauthenticated, errors.New("invalid credentials"))
}

func deviceID(d *pb.DeviceInfo) string {
	if d == nil {
		return ""
	}
	return d.DeviceId
}

func deviceType(d *pb.DeviceInfo, fallback string) string {
	if d == nil || d.DeviceType == "" {
		return fallback
	}
	return d.DeviceType
}

func deviceName(d *pb.DeviceInfo) string {
	if d == nil {
		return ""
	}
	return d.DeviceName
}

func firstNonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}

// pseudoSaltSecret is a process-local key used to derive stable but
// unpredictable salts for unknown emails. Initialised at startup from a
// random source so an attacker can't rederive the salt offline. Stable
// across the lifetime of one process — and that's the only window that
// matters for the timing-side-channel anti-enumeration goal.
var pseudoSaltSecret = func() []byte {
	b := make([]byte, 32)
	if _, err := readRandom(b); err != nil {
		// Falls back to all-zeros — the worst case is predictable salts,
		// not a crash. Logged in start.go via memguard CatchInterrupt.
		return b
	}
	return b
}()

// pseudoSalt returns a stable 16-byte salt for unknown emails so the
// "user does not exist" branch indistinguishable from the "user exists"
// one at the kdf level. HMAC-SHA256(secret, lower(email))[:16] guarantees
// a fixed length and hides the email content.
func pseudoSalt(email string) []byte {
	mac := hmac.New(sha256.New, pseudoSaltSecret)
	mac.Write([]byte(strings.ToLower(strings.TrimSpace(email))))
	return mac.Sum(nil)[:16]
}

// dummyAuthHash is a precomputed valid Argon2id PHC string derived from a
// random key. Used to pad the time of "no such user" branches in Authorize
// and RecoveryStart so the wall clock matches a real verify.
//
// Computed lazily via sync.Once because hashing is expensive (~50ms with
// the server params) and we don't want to slow down process startup when
// nobody is logging in yet.
var (
	dummyAuthHashOnce sync.Once
	dummyAuthHashVal  string
)

func dummyAuthHash() string {
	dummyAuthHashOnce.Do(func() {
		seed := make([]byte, 32)
		_, _ = readRandom(seed)
		// Use a fixed-but-conservative server-side Argon2 parameter set so
		// the timing matches real authentication. The exact params don't
		// have to mirror per-user state — VerifyAuthKey reads them from the
		// PHC string we hand it.
		h, err := auth.HashAuthKey(seed, auth.Argon2Params{T: 3, MKiB: 65536, P: 1})
		if err != nil {
			// Fall back to a known-bad string; VerifyAuthKey will return
			// false quickly. The anti-enumeration property degrades but
			// nothing breaks.
			dummyAuthHashVal = "$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			return
		}
		dummyAuthHashVal = h
	})
	return dummyAuthHashVal
}

// readRandom is a small wrapper so tests can stub the source if needed.
func readRandom(b []byte) (int, error) {
	return cryptoRand.Read(b)
}

func defaultKDFParams() *pb.Argon2Params {
	return &pb.Argon2Params{T: 3, MKib: 131072, P: 4, Algo: "argon2id"}
}

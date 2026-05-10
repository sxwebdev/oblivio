// Package auth implements the ConnectRPC AuthService handler.
package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/sxwebdev/oblivio/internal/api/gen/go/oblivio/v1"
	"github.com/sxwebdev/oblivio/internal/api/gen/go/oblivio/v1/obliviov1connect"
	"github.com/sxwebdev/oblivio/internal/api/middleware"
	"github.com/sxwebdev/oblivio/internal/audit"
	"github.com/sxwebdev/oblivio/internal/auth"
	"github.com/sxwebdev/oblivio/internal/config"
	"github.com/sxwebdev/oblivio/internal/models"
	"github.com/sxwebdev/oblivio/internal/store"
	"github.com/sxwebdev/oblivio/internal/store/repos"
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
	}
}

func (s *Service) logAudit(ctx context.Context, userID uuid.UUID, action models.AuditAction, req connect.AnyRequest, extra map[string]any) {
	if s.auditWriter == nil {
		return
	}
	meta := map[string]any{
		"procedure": req.Spec().Procedure,
	}
	for k, v := range extra {
		meta[k] = v
	}
	ev := audit.Event{
		Action:    action,
		UserAgent: req.Header().Get("User-Agent"),
		Metadata:  meta,
	}
	if userID != uuid.Nil {
		ev.UserID = uuid.NullUUID{UUID: userID, Valid: true}
		ev.TargetID = uuid.NullUUID{UUID: userID, Valid: true}
	}
	_, _ = s.auditWriter.Append(ctx, ev)
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

	s.logAudit(ctx, newUser.ID, models.AuditActionRegister, req, map[string]any{
		"device_id": deviceID(r.DeviceInfo),
	})

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
			return nil, unauthenticated()
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	ua, err := s.st.UserAuth().GetUserAuth(ctx, u.ID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	ok, err := auth.VerifyAuthKey(r.AuthKey, ua.AuthKeyHash)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if !ok {
		return nil, unauthenticated()
	}

	// Check 2FA state. Either TOTP enabled or registered passkeys triggers
	// an MFA challenge.
	totpRow, totpErr := s.st.UserLoginTOTP().GetUserLoginTOTP(ctx, u.ID)
	totpEnabled := totpErr == nil && totpRow != nil && totpRow.Enabled

	credCount := int64(0)
	if s.wa != nil {
		if c, err := s.st.UserWebAuthn().CountWebAuthnCredentials(ctx, u.ID); err == nil {
			credCount = c
		}
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
			creds, err := s.st.UserWebAuthn().ListWebAuthnCredentials(ctx, u.ID)
			if err != nil {
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
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid totp code"))
		}
	case hasWA:
		if s.wa == nil || ch.WebAuthnState == nil {
			return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("webauthn challenge not present"))
		}
		creds, err := s.st.UserWebAuthn().ListWebAuthnCredentials(ctx, ch.UserID)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		u, err := s.st.Users().GetUserByID(ctx, ch.UserID)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		wuser := buildWebAuthnUser(u, creds)
		parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(r.WebauthnAssertionJson))
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("parse assertion: %w", err))
		}
		credential, err := s.wa.ValidateLogin(wuser, *ch.WebAuthnState, parsed)
		if err != nil {
			return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("webauthn validate: %w", err))
		}
		// Update sign_count for the touched credential.
		matched, err := s.st.UserWebAuthn().GetWebAuthnCredentialByCredID(ctx, credential.ID)
		if err == nil {
			_ = s.st.UserWebAuthn().TouchWebAuthnCredential(ctx, repo_user_webauthn_credentials.TouchWebAuthnCredentialParams{
				ID:        matched.ID,
				SignCount: int64(credential.Authenticator.SignCount),
			})
		}
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
		return nil, unauthenticated()
	}

	uv, err := s.st.UserVault().GetUserVault(ctx, tokens.UserID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	s.logAudit(ctx, tokens.UserID, models.AuditActionRefresh, req, nil)

	return connect.NewResponse(&pb.RefreshTokenResponse{
		AuthPayload: buildAuthPayload(tokens, &payloadKeys{
			Verifier:        uv.Verifier,
			WrappedVaultKey: uv.WrappedVaultKey,
			VaultKeyVersion: uint32(uv.VaultKeyVersion),
		}),
	}), nil
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

	pool := s.st.Pool()
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := s.st.UserKDFParams(repos.WithTx(tx)).UpsertUserKDFParams(ctx, repo_user_kdf_params.UpsertUserKDFParamsParams{
		UserID:     sess.UserID,
		SaltUser:   r.SaltUser,
		Argon2T:    int32(r.KdfParams.GetT()),
		Argon2MKib: int32(r.KdfParams.GetMKib()),
		Argon2P:    int32(r.KdfParams.GetP()),
		Algo:       firstNonEmpty(r.KdfParams.GetAlgo(), "argon2id"),
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := s.st.UserAuth(repos.WithTx(tx)).UpsertUserAuth(ctx, repo_user_auth.UpsertUserAuthParams{
		UserID:      sess.UserID,
		AuthKeyHash: hashed,
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := s.st.UserVault(repos.WithTx(tx)).CompleteRecovery(ctx, repo_user_vault.CompleteRecoveryParams{
		UserID:          sess.UserID,
		Verifier:        r.Verifier,
		WrappedVaultKey: r.WrappedVaultKey,
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := s.st.AuthSessions(repos.WithTx(tx)).RevokeAllUserSessions(ctx, sess.UserID); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := tx.Commit(ctx); err != nil {
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
	return err != nil && strings.Contains(err.Error(), "23505")
}

func pseudoSalt(email string) []byte {
	out := make([]byte, 16)
	for i := 0; i < len(email) && i < 16; i++ {
		out[i] = email[i] ^ 0x5c
	}
	return out
}

func defaultKDFParams() *pb.Argon2Params {
	return &pb.Argon2Params{T: 3, MKib: 131072, P: 4, Algo: "argon2id"}
}

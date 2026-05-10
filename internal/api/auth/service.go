// Package auth implements the ConnectRPC AuthService handler.
package auth

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"
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
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_user_auth"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_user_kdf_params"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_user_vault"

	"github.com/google/uuid"
)

// Service implements the AuthService ConnectRPC contract.
type Service struct {
	obliviov1connect.UnimplementedAuthServiceHandler

	st                *store.Store
	am                *auth.Manager
	argon2            auth.Argon2Params
	auditWriter       *audit.Writer
	defaultDeviceType string
}

// NewService constructs the AuthService handler.
//
// auditWriter records register/login/logout/refresh events. AuthService
// procedures are on the anonymous allowlist so the audit-chain interceptor
// (which keys off the authenticated user_id) never runs against them — the
// handler must therefore log explicitly after the action succeeds.
func NewService(st *store.Store, am *auth.Manager, cfg config.AuthConfig, auditWriter *audit.Writer) *Service {
	return &Service{
		st: st,
		am: am,
		argon2: auth.Argon2Params{
			T:    cfg.Argon2Server.T,
			MKiB: cfg.Argon2Server.MKiB,
			P:    cfg.Argon2Server.P,
		},
		auditWriter:       auditWriter,
		defaultDeviceType: "web",
	}
}

// logAudit fires an audit-chain row for an auth event. Failures are
// swallowed deliberately — losing a chain row is preferable to failing a
// legitimate user-facing flow; the periodic verify job (Sprint 4) raises
// the alarm when entries are missing.
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
// The server never sees master_password or vault_key — only their derivations.
func (s *Service) Register(ctx context.Context, req *connect.Request[pb.RegisterRequest]) (*connect.Response[pb.RegisterResponse], error) {
	r := req.Msg
	if err := validateRegister(r); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	hashed, err := auth.HashAuthKey(r.AuthKey, s.argon2)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	// Per plan §5.5 the recovery_proof is HKDF(recovery_key, "oblivio/auth/v1");
	// we hash it with Argon2id once more before storing so a database leak
	// does not yield a directly-replayable proof.
	recoveryProofHash, err := auth.HashAuthKey(r.RecoveryProof, s.argon2)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	// Single transaction: user + kdf + auth + vault. If any step fails the
	// whole registration is rolled back.
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
// to re-derive master_key from master_password. Unknown emails receive
// deterministic pseudo-parameters to prevent user enumeration.
func (s *Service) GetKDFParams(ctx context.Context, req *connect.Request[pb.GetKDFParamsRequest]) (*connect.Response[pb.GetKDFParamsResponse], error) {
	email := strings.ToLower(strings.TrimSpace(req.Msg.Email))
	if email == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("email required"))
	}

	u, err := s.st.Users().GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Anti-enumeration: stable pseudo-parameters per email.
			// Sprint 4 will add a server-secret HKDF; for MVP we just return
			// defaults so the client cannot distinguish from a real account
			// until Authorize fails.
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

// Authorize verifies the client-supplied auth_key against the stored hash
// and issues a fresh access/refresh token pair on success.
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

	uv, err := s.st.UserVault().GetUserVault(ctx, u.ID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	tokens, err := s.am.Issue(ctx, u.ID, deviceID(r.DeviceInfo), deviceType(r.DeviceInfo, s.defaultDeviceType), deviceName(r.DeviceInfo))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	s.logAudit(ctx, u.ID, models.AuditActionLogin, req, map[string]any{
		"device_id": deviceID(r.DeviceInfo),
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
// its key tree (verifier + wrapped_vault_key). The server cannot decrypt these.
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
	// Identical message for unknown email and wrong password — anti-enumeration.
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

// pseudoSalt returns 16 deterministic bytes for an unknown email. The current
// implementation is a placeholder — Sprint 4 will derive it via HKDF with a
// server-side secret so it cannot be distinguished from a real salt.
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

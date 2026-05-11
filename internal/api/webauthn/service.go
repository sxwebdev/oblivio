// Package webauthn implements the WebAuthnService ConnectRPC handler.
//
// Registration ceremonies are stateful: RegisterBegin returns a session_id
// the client must echo back in RegisterFinish. Sessions live in the shared
// auth.MFAStore alongside login challenges.
package webauthn

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
	"github.com/sxwebdev/oblivio/internal/models"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_user_webauthn_credentials"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_users"
)

// Service implements WebAuthnService.
type Service struct {
	obliviov1connect.UnimplementedWebAuthnServiceHandler

	wa          *wa.WebAuthn
	mfa         *auth.MFAStore
	auditWriter *audit.Writer
}

// NewService constructs a handler bound to a configured WebAuthn relying party.
func NewService(rp *wa.WebAuthn, mfa *auth.MFAStore, auditWriter *audit.Writer) *Service {
	return &Service{wa: rp, mfa: mfa, auditWriter: auditWriter}
}

// RegisterBegin starts a registration ceremony. The session_id we return is
// the UUID of the MFA-store entry holding the SessionData for the in-flight
// ceremony. The session is consumed by RegisterFinish.
func (s *Service) RegisterBegin(ctx context.Context, req *connect.Request[pb.RegisterBeginRequest]) (*connect.Response[pb.RegisterBeginResponse], error) {
	if s.wa == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("webauthn not configured"))
	}
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)

	u, err := repo_users.New(tx).GetUserByID(ctx, uc.UserID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	creds, err := repo_user_webauthn_credentials.New(tx).ListWebAuthnCredentials(ctx, uc.UserID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	user := newUser(u, creds)

	// Force user-verification at registration. Without UV=required the
	// library default is "preferred", which would accept a passkey backed
	// only by proof-of-possession (no PIN / no biometric) — too weak for a
	// secret-manager second factor (see plan §5.4).
	options, session, err := s.wa.BeginRegistration(
		user,
		wa.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
		}),
	)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("begin registration: %w", err))
	}

	// Stash the user-supplied credential name in the MFA challenge's
	// DeviceName slot so RegisterFinish can reach it without an extra
	// DB roundtrip. chooseName() consumes it as the friendly label.
	sessionID, err := s.mfa.Put(ctx, auth.MFAChallenge{
		UserID:        uc.UserID,
		Email:         u.Email,
		DeviceName:    strings.TrimSpace(req.Msg.GetCredentialName()),
		WebAuthnState: session,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("mfa challenge put: %w", err))
	}

	optBytes, err := json.Marshal(options)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&pb.RegisterBeginResponse{
		SessionId:   sessionID.String(),
		OptionsJson: optBytes,
	}), nil
}

// RegisterFinish completes registration, persisting the new credential.
func (s *Service) RegisterFinish(ctx context.Context, req *connect.Request[pb.RegisterFinishRequest]) (*connect.Response[pb.RegisterFinishResponse], error) {
	if s.wa == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("webauthn not configured"))
	}
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)

	sid, err := uuid.Parse(req.Msg.SessionId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid session_id"))
	}
	challenge, err := s.mfa.Take(ctx, sid)
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("registration session expired"))
	}
	if challenge.UserID != uc.UserID || challenge.WebAuthnState == nil {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("session does not belong to caller"))
	}

	u, err := repo_users.New(tx).GetUserByID(ctx, uc.UserID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	wuser := newUser(u, nil)

	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(req.Msg.AttestationJson))
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("parse attestation: %w", err))
	}
	cred, err := s.wa.CreateCredential(wuser, *challenge.WebAuthnState, parsed)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("create credential: %w", err))
	}

	// Prefer the name the user typed at RegisterBegin (stashed in the
	// MFA challenge's DeviceName slot). Fall back to AAGUID-based label.
	name := chooseName(challenge.DeviceName, parsed)

	transports := transportsAsStrings(cred.Transport)

	row, err := repo_user_webauthn_credentials.New(tx).CreateWebAuthnCredential(ctx, repo_user_webauthn_credentials.CreateWebAuthnCredentialParams{
		UserID:       uc.UserID,
		Name:         name,
		CredentialID: cred.ID,
		PublicKey:    cred.PublicKey,
		Aaguid:       cred.Authenticator.AAGUID,
		SignCount:    int64(cred.Authenticator.SignCount),
		Transports:   transports,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	middleware.SetAuditTarget(ctx, row.ID)

	return connect.NewResponse(&pb.RegisterFinishResponse{
		CredentialId: row.ID.String(),
		Name:         row.Name,
	}), nil
}

// ListCredentials returns metadata for the user's enrolled authenticators.
func (s *Service) ListCredentials(ctx context.Context, _ *connect.Request[pb.ListCredentialsRequest]) (*connect.Response[pb.ListCredentialsResponse], error) {
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)

	creds, err := repo_user_webauthn_credentials.New(tx).ListWebAuthnCredentials(ctx, uc.UserID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := make([]*pb.WebAuthnCredential, 0, len(creds))
	for _, c := range creds {
		item := &pb.WebAuthnCredential{
			Id:         c.ID.String(),
			Name:       c.Name,
			Transports: c.Transports,
		}
		if c.CreatedAt.Valid {
			item.CreatedAt = timestamppb.New(c.CreatedAt.Time)
		}
		if c.LastUsedAt.Valid {
			item.LastUsedAt = timestamppb.New(c.LastUsedAt.Time)
		}
		out = append(out, item)
	}
	return connect.NewResponse(&pb.ListCredentialsResponse{Credentials: out}), nil
}

// BeginAssertion seeds a re-authentication challenge for the calling user.
// The returned session_id is later passed to whichever service consumes the
// assertion (currently LoginTOTPService.Disable). The MFAStore entry holds
// the WebAuthn SessionData so we can validate the assertion against the
// original challenge.
func (s *Service) BeginAssertion(ctx context.Context, _ *connect.Request[pb.BeginAssertionRequest]) (*connect.Response[pb.BeginAssertionResponse], error) {
	if s.wa == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("webauthn not configured"))
	}
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)

	u, err := repo_users.New(tx).GetUserByID(ctx, uc.UserID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	creds, err := repo_user_webauthn_credentials.New(tx).ListWebAuthnCredentials(ctx, uc.UserID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if len(creds) == 0 {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("no credentials enrolled"))
	}
	wuser := newUser(u, creds)

	// UV=required (see RegisterBegin for rationale).
	options, session, err := s.wa.BeginLogin(
		wuser,
		wa.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("begin assertion: %w", err))
	}
	sid, err := s.mfa.Put(ctx, auth.MFAChallenge{
		UserID:        uc.UserID,
		Email:         u.Email,
		WebAuthnState: session,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("mfa challenge put: %w", err))
	}
	optBytes, err := json.Marshal(options)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&pb.BeginAssertionResponse{
		SessionId:   sid.String(),
		OptionsJson: optBytes,
	}), nil
}

// RemoveCredential deletes a stored credential.
func (s *Service) RemoveCredential(ctx context.Context, req *connect.Request[pb.RemoveCredentialRequest]) (*connect.Response[pb.RemoveCredentialResponse], error) {
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)

	id, err := uuid.Parse(req.Msg.CredentialId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid credential_id"))
	}
	cred, err := repo_user_webauthn_credentials.New(tx).GetWebAuthnCredentialByID(ctx, repo_user_webauthn_credentials.GetWebAuthnCredentialByIDParams{
		ID:     id,
		UserID: uc.UserID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("credential not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := repo_user_webauthn_credentials.New(tx).DeleteWebAuthnCredential(ctx, repo_user_webauthn_credentials.DeleteWebAuthnCredentialParams{
		ID:     id,
		UserID: uc.UserID,
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	middleware.SetAuditTarget(ctx, cred.ID)
	return connect.NewResponse(&pb.RemoveCredentialResponse{}), nil
}

// --- helpers ---

func chooseName(userSupplied string, attestation *protocol.ParsedCredentialCreationData) string {
	// User-supplied label wins. Fall back to a short AAGUID-derived label
	// so users still see something more meaningful than "passkey".
	if s := strings.TrimSpace(userSupplied); s != "" {
		return s
	}
	if attestation != nil {
		return "passkey-" + shortHex(attestation.Response.AttestationObject.AuthData.AttData.AAGUID)
	}
	return "passkey"
}

func shortHex(b []byte) string {
	if len(b) == 0 {
		return "unknown"
	}
	const hex = "0123456789abcdef"
	if len(b) > 4 {
		b = b[:4]
	}
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, hex[x>>4], hex[x&0x0f])
	}
	return string(out)
}

func transportsAsStrings(in []protocol.AuthenticatorTransport) []string {
	out := make([]string, 0, len(in))
	for _, t := range in {
		out = append(out, string(t))
	}
	return out
}

// LoadCredentials is a convenience for the auth/login flow: it returns the
// credentials persisted for a user via a direct repo call.
func LoadCredentials(ctx context.Context, tx pgx.Tx, userID uuid.UUID) ([]*models.UserWebauthnCredential, error) {
	return repo_user_webauthn_credentials.New(tx).ListWebAuthnCredentials(ctx, userID)
}

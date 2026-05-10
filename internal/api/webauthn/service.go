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

	options, session, err := s.wa.BeginRegistration(user)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("begin registration: %w", err))
	}

	sessionID := s.mfa.Put(auth.MFAChallenge{
		UserID:        uc.UserID,
		Email:         u.Email,
		WebAuthnState: session,
	})

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
	challenge, err := s.mfa.Take(sid)
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

	name := chooseName(req.Msg.GetSessionId(), parsed)

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

func chooseName(fallback string, attestation *protocol.ParsedCredentialCreationData) string {
	// The CredentialName is shipped through the session; we plumb it
	// through MFAStore in RegisterBegin via the DeviceName slot to keep
	// the struct narrow. As a fallback (or when the caller didn't supply
	// one) we use the attestation AAGUID hex.
	if attestation != nil {
		return "passkey-" + shortHex(attestation.Response.AttestationObject.AuthData.AttData.AAGUID)
	}
	if fallback != "" {
		return fallback
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

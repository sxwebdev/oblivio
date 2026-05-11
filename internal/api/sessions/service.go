// Package sessions implements the SessionsService ConnectRPC handler.
//
// Sessions are stored in auth_sessions and managed by internal/auth.Manager.
// This package only owns the user-facing list/terminate surface — the token
// issuance path lives in the auth service. Termination delegates to the
// Manager so the underlying access/refresh tokens in auth_tokens are
// deleted alongside the session row, otherwise revocation would only flip
// a DB flag that nobody consults.
package sessions

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/sxwebdev/oblivio/internal/api/gen/go/oblivio/v1"
	"github.com/sxwebdev/oblivio/internal/api/gen/go/oblivio/v1/obliviov1connect"
	"github.com/sxwebdev/oblivio/internal/api/middleware"
	"github.com/sxwebdev/oblivio/internal/audit"
	"github.com/sxwebdev/oblivio/internal/auth"
	"github.com/sxwebdev/oblivio/internal/metrics"
	"github.com/sxwebdev/oblivio/internal/models"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_auth_sessions"
)

// Service implements SessionsService.
type Service struct {
	obliviov1connect.UnimplementedSessionsServiceHandler
	auditWriter *audit.Writer
	authManager *auth.Manager
}

// NewService builds the handler.
func NewService(auditWriter *audit.Writer, am *auth.Manager) *Service {
	return &Service{auditWriter: auditWriter, authManager: am}
}

// ListSessions returns every non-revoked session that belongs to the
// caller. RLS keeps the result scoped even if we omit the WHERE clause —
// we still pass user_id for clarity and efficiency.
func (s *Service) ListSessions(ctx context.Context, _ *connect.Request[pb.ListSessionsRequest]) (*connect.Response[pb.ListSessionsResponse], error) {
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)

	rows, err := repo_auth_sessions.New(tx).ListUserSessions(ctx, uc.UserID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := make([]*pb.Session, 0, len(rows))
	for _, r := range rows {
		out = append(out, toPBSession(r, r.ID == uc.SessionID))
	}
	return connect.NewResponse(&pb.ListSessionsResponse{Sessions: out}), nil
}

// TerminateSession revokes a single session. The caller may revoke their
// own session (effectively a remote logout) — the next access-token check
// will fail because the row is no longer in (revoked_at IS NULL).
func (s *Service) TerminateSession(ctx context.Context, req *connect.Request[pb.TerminateSessionRequest]) (*connect.Response[pb.TerminateSessionResponse], error) {
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)

	id, err := uuid.Parse(req.Msg.SessionId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid session_id"))
	}

	// Ownership check first: GetSessionByID is RLS-scoped through the tx,
	// so a foreign session_id is invisible. Defence in depth — if RLS were
	// disabled the check below would still gate the revoke.
	repo := repo_auth_sessions.New(tx)
	row, err := repo.GetSessionByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("session not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if row.UserID != uc.UserID {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("session not found"))
	}

	// Authoritative revoke: drops the access+refresh rows from auth_tokens
	// AND flips the auth_sessions row revoked_at. Without the token-side
	// delete the access token would stay valid until natural expiry.
	if err := s.authManager.RevokeSession(ctx, id); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	metrics.SessionsTerminatedTotal.WithLabelValues("self").Inc()
	middleware.SetAuditTarget(ctx, id)
	s.writeAudit(ctx, uc.UserID, id, req.Header().Get("User-Agent"), "single")

	return connect.NewResponse(&pb.TerminateSessionResponse{}), nil
}

// TerminateAllExceptCurrent revokes every other session belonging to the
// caller. Useful as the "I think I was compromised" big red button.
//
// Two parallel sweeps run: the token store (auth_tokens) drops every token
// row except those bound to the current session, and auth_sessions flips
// revoked_at on every row except the current one.
func (s *Service) TerminateAllExceptCurrent(ctx context.Context, req *connect.Request[pb.TerminateAllExceptCurrentRequest]) (*connect.Response[pb.TerminateAllExceptCurrentResponse], error) {
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)

	// Drop every token for the user except the current session's pair.
	if err := s.authManager.RevokeUserTokensExceptSession(ctx, uc.UserID, uc.SessionID); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	n, err := repo_auth_sessions.New(tx).RevokeAllUserSessionsExcept(ctx,
		repo_auth_sessions.RevokeAllUserSessionsExceptParams{
			UserID: uc.UserID,
			ID:     uc.SessionID,
		})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	metrics.SessionsTerminatedTotal.WithLabelValues("all_except_current").Add(float64(n))
	s.writeAudit(ctx, uc.UserID, uuid.Nil, req.Header().Get("User-Agent"), "all_except_current")

	return connect.NewResponse(&pb.TerminateAllExceptCurrentResponse{
		TerminatedCount: uint32(n), //nolint:gosec
	}), nil
}

func (s *Service) writeAudit(ctx context.Context, userID, target uuid.UUID, ua, scope string) {
	if s.auditWriter == nil {
		return
	}
	ev := audit.Event{
		UserID:    uuid.NullUUID{UUID: userID, Valid: true},
		Action:    models.AuditActionSessionTerminate,
		UserAgent: ua,
		Metadata:  map[string]any{"scope": scope},
	}
	if target != uuid.Nil {
		ev.TargetID = uuid.NullUUID{UUID: target, Valid: true}
	}
	s.auditWriter.AppendOrLog(ctx, ev)
}

func toPBSession(r *models.AuthSession, current bool) *pb.Session {
	p := &pb.Session{
		Id:               r.ID.String(),
		DeviceId:         r.DeviceID,
		DeviceType:       r.DeviceType,
		CreatedAt:        timestamppb.New(r.CreatedAt.Time),
		LastSeenAt:       timestamppb.New(r.LastSeenAt.Time),
		AccessExpiresAt:  timestamppb.New(r.AccessExpiresAt.Time),
		RefreshExpiresAt: timestamppb.New(r.RefreshExpiresAt.Time),
		IsCurrent:        current,
	}
	if r.DeviceName.Valid {
		v := r.DeviceName.String
		p.DeviceName = &v
	}
	if r.Ip != nil {
		v := r.Ip.String()
		p.Ip = &v
	}
	if r.Country.Valid {
		v := r.Country.String
		p.Country = &v
	}
	return p
}

// Package sessions implements the SessionsService ConnectRPC handler.
//
// Sessions are stored in auth_sessions and managed by internal/auth.Manager.
// This package only owns the user-facing list/terminate surface — the token
// issuance path lives in the auth service.
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
	"github.com/sxwebdev/oblivio/internal/metrics"
	"github.com/sxwebdev/oblivio/internal/models"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_auth_sessions"
)

// Service implements SessionsService.
type Service struct {
	obliviov1connect.UnimplementedSessionsServiceHandler
	auditWriter *audit.Writer
}

// NewService builds the handler.
func NewService(auditWriter *audit.Writer) *Service {
	return &Service{auditWriter: auditWriter}
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

	repo := repo_auth_sessions.New(tx)
	row, err := repo.GetSessionByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("session not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if row.UserID != uc.UserID {
		// RLS should have masked this anyway; defence in depth.
		return nil, connect.NewError(connect.CodeNotFound, errors.New("session not found"))
	}

	if err := repo.RevokeSession(ctx, id); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	metrics.SessionsTerminatedTotal.WithLabelValues("self").Inc()
	middleware.SetAuditTarget(ctx, id)
	s.writeAudit(ctx, uc.UserID, id, req.Header().Get("User-Agent"), "single")

	return connect.NewResponse(&pb.TerminateSessionResponse{}), nil
}

// TerminateAllExceptCurrent revokes every other session belonging to the
// caller. Useful as the "I think I was compromised" big red button.
func (s *Service) TerminateAllExceptCurrent(ctx context.Context, req *connect.Request[pb.TerminateAllExceptCurrentRequest]) (*connect.Response[pb.TerminateAllExceptCurrentResponse], error) {
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)

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
	_, _ = s.auditWriter.Append(ctx, ev)
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

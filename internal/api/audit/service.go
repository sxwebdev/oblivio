// Package audit implements the AuditService ConnectRPC handler.
//
// The handler is read-only: the chain writer (internal/audit) runs in the
// audit interceptor and authentication paths. Clients can list their own
// records (RLS guarantees scoping even if the WHERE clause is forgotten).
package audit

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/sxwebdev/oblivio/internal/api/gen/go/oblivio/v1"
	"github.com/sxwebdev/oblivio/internal/api/gen/go/oblivio/v1/obliviov1connect"
	"github.com/sxwebdev/oblivio/internal/api/middleware"
	"github.com/sxwebdev/oblivio/internal/models"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_audit_log"
)

const (
	defaultAuditLimit = 50
	maxAuditLimit     = 200
)

// Service implements AuditService.
type Service struct {
	obliviov1connect.UnimplementedAuditServiceHandler
}

// NewService builds the handler.
func NewService() *Service { return &Service{} }

// ListAudit returns the caller's audit entries filtered by action and
// time range, paginated newest-first.
func (s *Service) ListAudit(ctx context.Context, req *connect.Request[pb.ListAuditRequest]) (*connect.Response[pb.ListAuditResponse], error) {
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)
	limit := int32(req.Msg.Limit)
	if limit <= 0 {
		limit = defaultAuditLimit
	}
	if limit > maxAuditLimit {
		limit = maxAuditLimit
	}

	params := repo_audit_log.ListAuditEntriesParams{
		UserID:    uuid.NullUUID{UUID: uc.UserID, Valid: true},
		PageLimit: limit,
	}
	if req.Msg.Action != nil {
		action, err := toModelAction(*req.Msg.Action)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		params.ActionFilter = repo_audit_log.NullAuditAction{AuditAction: action, Valid: true}
	}
	if req.Msg.From != nil {
		params.FromTime = pgtype.Timestamptz{Time: req.Msg.From.AsTime(), Valid: true}
	}
	if req.Msg.To != nil {
		params.ToTime = pgtype.Timestamptz{Time: req.Msg.To.AsTime(), Valid: true}
	}
	if req.Msg.CursorId != nil {
		params.CursorID = pgtype.Int8{Int64: *req.Msg.CursorId, Valid: true}
	}

	rows, err := repo_audit_log.New(tx).ListAuditEntries(ctx, params)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := make([]*pb.AuditEntry, 0, len(rows))
	for _, r := range rows {
		out = append(out, toAuditEntry(r))
	}
	resp := &pb.ListAuditResponse{Entries: out}
	if len(rows) == int(limit) && len(rows) > 0 {
		next := rows[len(rows)-1].ID
		resp.NextCursorId = &next
	}
	return connect.NewResponse(resp), nil
}

func toAuditEntry(r *models.AuditLog) *pb.AuditEntry {
	e := &pb.AuditEntry{
		Id:           r.ID,
		Action:       fromModelAction(r.Action),
		MetadataJson: r.Metadata,
		PrevHash:     r.PrevHash,
		SelfHash:     r.SelfHash,
		CreatedAt:    timestamppb.New(r.CreatedAt.Time),
	}
	if r.TargetID.Valid {
		t := r.TargetID.UUID.String()
		e.TargetId = &t
	}
	if r.Ip != nil {
		ip := r.Ip.String()
		e.Ip = &ip
	}
	if r.UserAgent.Valid {
		ua := r.UserAgent.String
		e.UserAgent = &ua
	}
	return e
}

var actionByProto = map[pb.AuditAction]models.AuditAction{
	pb.AuditAction_AUDIT_ACTION_REGISTER:          models.AuditActionRegister,
	pb.AuditAction_AUDIT_ACTION_LOGIN:             models.AuditActionLogin,
	pb.AuditAction_AUDIT_ACTION_LOGOUT:            models.AuditActionLogout,
	pb.AuditAction_AUDIT_ACTION_REFRESH:           models.AuditActionRefresh,
	pb.AuditAction_AUDIT_ACTION_PASSWORD_CHANGE:   models.AuditActionPasswordChange,
	pb.AuditAction_AUDIT_ACTION_RECOVERY_START:    models.AuditActionRecoveryStart,
	pb.AuditAction_AUDIT_ACTION_RECOVERY_COMPLETE: models.AuditActionRecoveryComplete,
	pb.AuditAction_AUDIT_ACTION_WEBAUTHN_REGISTER: models.AuditActionWebauthnRegister,
	pb.AuditAction_AUDIT_ACTION_WEBAUTHN_REMOVE:   models.AuditActionWebauthnRemove,
	pb.AuditAction_AUDIT_ACTION_TOTP_ENABLE:       models.AuditActionTotpEnable,
	pb.AuditAction_AUDIT_ACTION_TOTP_DISABLE:      models.AuditActionTotpDisable,
	pb.AuditAction_AUDIT_ACTION_PROJECT_CREATE:    models.AuditActionProjectCreate,
	pb.AuditAction_AUDIT_ACTION_PROJECT_UPDATE:    models.AuditActionProjectUpdate,
	pb.AuditAction_AUDIT_ACTION_PROJECT_DELETE:    models.AuditActionProjectDelete,
	pb.AuditAction_AUDIT_ACTION_ENTRY_CREATE:      models.AuditActionEntryCreate,
	pb.AuditAction_AUDIT_ACTION_ENTRY_UPDATE:      models.AuditActionEntryUpdate,
	pb.AuditAction_AUDIT_ACTION_ENTRY_VIEW:        models.AuditActionEntryView,
	pb.AuditAction_AUDIT_ACTION_ENTRY_DELETE:      models.AuditActionEntryDelete,
	pb.AuditAction_AUDIT_ACTION_SESSION_TERMINATE: models.AuditActionSessionTerminate,
	pb.AuditAction_AUDIT_ACTION_ACCOUNT_DELETE:    models.AuditActionAccountDelete,
	pb.AuditAction_AUDIT_ACTION_EMAIL_VERIFY:                  models.AuditActionEmailVerify,
	pb.AuditAction_AUDIT_ACTION_EMAIL_RESEND:                  models.AuditActionEmailResend,
	pb.AuditAction_AUDIT_ACTION_ACCOUNT_DELETE_ATTEMPT_FAILED: models.AuditActionAccountDeleteAttemptFailed,
}

var protoByAction = func() map[models.AuditAction]pb.AuditAction {
	m := make(map[models.AuditAction]pb.AuditAction, len(actionByProto))
	for k, v := range actionByProto {
		m[v] = k
	}
	return m
}()

func toModelAction(a pb.AuditAction) (models.AuditAction, error) {
	v, ok := actionByProto[a]
	if !ok {
		return "", errors.New("unknown audit action")
	}
	return v, nil
}

func fromModelAction(a models.AuditAction) pb.AuditAction {
	if v, ok := protoByAction[a]; ok {
		return v
	}
	return pb.AuditAction_AUDIT_ACTION_UNSPECIFIED
}

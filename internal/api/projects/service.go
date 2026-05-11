// Package projects implements the ProjectsService ConnectRPC handler.
//
// All handlers are wrapped by the RLS interceptor (middleware.NewRLSInterceptor)
// and therefore run inside a request-scoped transaction with
// `app.current_user_id` set. Reads/writes go through the tx-bound repo.
package projects

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
	apisubs "github.com/sxwebdev/oblivio/internal/api/subscriptions"
	"github.com/sxwebdev/oblivio/internal/models"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_projects"
)

// Service implements ProjectsService.
type Service struct {
	obliviov1connect.UnimplementedProjectsServiceHandler
}

// NewService constructs the handler. It is intentionally stateless — every
// call pulls the per-request transaction from context.
func NewService() *Service { return &Service{} }

// ListProjects returns all projects belonging to the caller, ordered by
// sort_order then creation time.
func (s *Service) ListProjects(ctx context.Context, _ *connect.Request[pb.ListProjectsRequest]) (*connect.Response[pb.ListProjectsResponse], error) {
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)
	rows, err := repo_projects.New(tx).ListProjects(ctx, uc.UserID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := make([]*pb.Project, 0, len(rows))
	for _, r := range rows {
		out = append(out, toProject(r))
	}
	return connect.NewResponse(&pb.ListProjectsResponse{Projects: out}), nil
}

// GetProject fetches a single project by id.
func (s *Service) GetProject(ctx context.Context, req *connect.Request[pb.GetProjectRequest]) (*connect.Response[pb.GetProjectResponse], error) {
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid project id"))
	}
	row, err := repo_projects.New(tx).GetProject(ctx, repo_projects.GetProjectParams{ID: id, UserID: uc.UserID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("project not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&pb.GetProjectResponse{Project: toProject(row)}), nil
}

// CreateProject inserts a new project. All payload fields are opaque
// ciphertext to the server.
func (s *Service) CreateProject(ctx context.Context, req *connect.Request[pb.CreateProjectRequest]) (*connect.Response[pb.CreateProjectResponse], error) {
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)
	if err := validateBlob(req.Msg.EncryptedBlob, req.Msg.WrappedItemKey, req.Msg.NameHash); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	row, err := repo_projects.New(tx).CreateProject(ctx, repo_projects.CreateProjectParams{
		UserID:         uc.UserID,
		EncryptedBlob:  req.Msg.EncryptedBlob,
		WrappedItemKey: req.Msg.WrappedItemKey,
		NameHash:       req.Msg.NameHash,
		SortOrder:      req.Msg.SortOrder,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	middleware.SetAuditTarget(ctx, row.ID)
	if err := apisubs.PublishProjectsChanged(ctx, tx, uc.UserID); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&pb.CreateProjectResponse{Project: toProject(row)}), nil
}

// UpdateProject overwrites blob+wrapped_key+name_hash using optimistic
// concurrency on `expected_version`.
func (s *Service) UpdateProject(ctx context.Context, req *connect.Request[pb.UpdateProjectRequest]) (*connect.Response[pb.UpdateProjectResponse], error) {
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid project id"))
	}
	if err := validateBlob(req.Msg.EncryptedBlob, req.Msg.WrappedItemKey, req.Msg.NameHash); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	row, err := repo_projects.New(tx).UpdateProject(ctx, repo_projects.UpdateProjectParams{
		ID:              id,
		UserID:          uc.UserID,
		EncryptedBlob:   req.Msg.EncryptedBlob,
		WrappedItemKey:  req.Msg.WrappedItemKey,
		NameHash:        req.Msg.NameHash,
		ExpectedVersion: int32(req.Msg.ExpectedVersion),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("project missing or version mismatch"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	middleware.SetAuditTarget(ctx, row.ID)
	if err := apisubs.PublishProjectsChanged(ctx, tx, uc.UserID); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&pb.UpdateProjectResponse{Project: toProject(row)}), nil
}

// DeleteProject hard-deletes a project. The version check rejects stale
// retries. Associated entries' project_id is set NULL by FK ON DELETE.
func (s *Service) DeleteProject(ctx context.Context, req *connect.Request[pb.DeleteProjectRequest]) (*connect.Response[pb.DeleteProjectResponse], error) {
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid project id"))
	}
	rows, err := repo_projects.New(tx).DeleteProject(ctx, repo_projects.DeleteProjectParams{
		ID:              id,
		UserID:          uc.UserID,
		ExpectedVersion: int32(req.Msg.ExpectedVersion),
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if rows == 0 {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("project missing or version mismatch"))
	}
	middleware.SetAuditTarget(ctx, id)
	if err := apisubs.PublishProjectsChanged(ctx, tx, uc.UserID); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&pb.DeleteProjectResponse{}), nil
}

// ReorderProjects re-numbers sort_order for a batch of ids in O(n) writes.
func (s *Service) ReorderProjects(ctx context.Context, req *connect.Request[pb.ReorderProjectsRequest]) (*connect.Response[pb.ReorderProjectsResponse], error) {
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)
	q := repo_projects.New(tx)
	for i, raw := range req.Msg.OrderedIds {
		id, err := uuid.Parse(raw)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid project id"))
		}
		if err := q.ReorderProject(ctx, repo_projects.ReorderProjectParams{
			ID:        id,
			UserID:    uc.UserID,
			SortOrder: int32(i),
		}); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
	}
	if err := apisubs.PublishProjectsChanged(ctx, tx, uc.UserID); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&pb.ReorderProjectsResponse{}), nil
}

func toProject(r *models.Project) *pb.Project {
	return &pb.Project{
		Id:             r.ID.String(),
		EncryptedBlob:  r.EncryptedBlob,
		WrappedItemKey: r.WrappedItemKey,
		NameHash:       r.NameHash,
		Version:        uint32(r.Version),
		SortOrder:      r.SortOrder,
		CreatedAt:      timestamppb.New(r.CreatedAt.Time),
		UpdatedAt:      timestamppb.New(r.UpdatedAt.Time),
	}
}

func validateBlob(blob, wrappedKey, nameHash []byte) error {
	// Minimal envelope = 1 byte version + 12 byte nonce + 16 byte tag = 29.
	if len(blob) < 29 {
		return errors.New("encrypted_blob too short")
	}
	if len(wrappedKey) < 29 {
		return errors.New("wrapped_item_key too short")
	}
	if len(nameHash) != 32 {
		return errors.New("name_hash must be SHA-256 (32 bytes)")
	}
	return nil
}

// Package entries implements the EntriesService ConnectRPC handler.
//
// Like projects, every handler runs inside the per-request RLS transaction
// installed by middleware.NewRLSInterceptor. Cipher payloads are opaque
// to the server; only the boolean flags and *_hash columns shape filtering
// and indexing.
package entries

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/sxwebdev/oblivio/internal/api/gen/go/oblivio/v1"
	"github.com/sxwebdev/oblivio/internal/api/gen/go/oblivio/v1/obliviov1connect"
	"github.com/sxwebdev/oblivio/internal/api/middleware"
	"github.com/sxwebdev/oblivio/internal/metrics"
	"github.com/sxwebdev/oblivio/internal/models"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_entries"
)

const (
	defaultListLimit = 100
	maxListLimit     = 500
	maxBatchGet      = 200
)

// Service implements EntriesService.
type Service struct {
	obliviov1connect.UnimplementedEntriesServiceHandler
}

// NewService builds a stateless handler.
func NewService() *Service { return &Service{} }

// ListEntries returns metadata (no cipher payload) for the caller's
// entries matching the supplied filters. The next-page cursor is the
// updated_at of the last row.
func (s *Service) ListEntries(ctx context.Context, req *connect.Request[pb.ListEntriesRequest]) (*connect.Response[pb.ListEntriesResponse], error) {
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)
	params, err := buildListParams(uc.UserID, req.Msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	rows, err := repo_entries.New(tx).ListEntries(ctx, params)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := make([]*pb.EntryMeta, 0, len(rows))
	for _, r := range rows {
		out = append(out, toEntryMeta(r))
	}
	resp := &pb.ListEntriesResponse{Entries: out}
	if len(rows) == int(params.PageLimit) && len(rows) > 0 {
		last := rows[len(rows)-1]
		resp.NextUpdatedAfter = timestamppb.New(last.UpdatedAt.Time)
	}
	return connect.NewResponse(resp), nil
}

// GetEntriesByIds returns full cipher payloads for a batch of ids.
// Marked as an audit event ("entry_view") because decryption requires it.
func (s *Service) GetEntriesByIds(ctx context.Context, req *connect.Request[pb.GetEntriesByIdsRequest]) (*connect.Response[pb.GetEntriesByIdsResponse], error) {
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)
	if len(req.Msg.Ids) == 0 {
		return connect.NewResponse(&pb.GetEntriesByIdsResponse{}), nil
	}
	if len(req.Msg.Ids) > maxBatchGet {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("too many ids in one batch"))
	}
	ids, err := parseUUIDs(req.Msg.Ids)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	rows, err := repo_entries.New(tx).GetEntriesByIDs(ctx, repo_entries.GetEntriesByIDsParams{
		UserID: uc.UserID,
		Ids:    ids,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := make([]*pb.Entry, 0, len(rows))
	for _, r := range rows {
		out = append(out, toEntry(r))
	}
	if len(rows) == 1 {
		middleware.SetAuditTarget(ctx, rows[0].ID)
	}
	metrics.EntryViewsTotal.Add(float64(len(rows)))
	return connect.NewResponse(&pb.GetEntriesByIdsResponse{Entries: out}), nil
}

// GetEntry fetches a single full entry.
func (s *Service) GetEntry(ctx context.Context, req *connect.Request[pb.GetEntryRequest]) (*connect.Response[pb.GetEntryResponse], error) {
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid entry id"))
	}
	row, err := repo_entries.New(tx).GetEntry(ctx, repo_entries.GetEntryParams{ID: id, UserID: uc.UserID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("entry not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&pb.GetEntryResponse{Entry: toEntry(row)}), nil
}

// CreateEntry persists a new ciphertext record.
func (s *Service) CreateEntry(ctx context.Context, req *connect.Request[pb.CreateEntryRequest]) (*connect.Response[pb.CreateEntryResponse], error) {
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)
	if err := validateBlob(req.Msg.EncryptedBlob, req.Msg.WrappedItemKey, req.Msg.TitleHash); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	kind, err := toModelKind(req.Msg.Kind)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	projectID, err := optionalUUID(req.Msg.ProjectId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	row, err := repo_entries.New(tx).CreateEntry(ctx, repo_entries.CreateEntryParams{
		UserID:         uc.UserID,
		ProjectID:      projectID,
		Kind:           kind,
		EncryptedBlob:  req.Msg.EncryptedBlob,
		WrappedItemKey: req.Msg.WrappedItemKey,
		TitleHash:      req.Msg.TitleHash,
		DomainHash:     req.Msg.DomainHash,
		HasTotp:        req.Msg.HasTotp,
		IsFavorite:     req.Msg.IsFavorite,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	middleware.SetAuditTarget(ctx, row.ID)
	return connect.NewResponse(&pb.CreateEntryResponse{Entry: toEntry(row)}), nil
}

// UpdateEntry overwrites all mutable fields with optimistic concurrency.
func (s *Service) UpdateEntry(ctx context.Context, req *connect.Request[pb.UpdateEntryRequest]) (*connect.Response[pb.UpdateEntryResponse], error) {
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid entry id"))
	}
	if err := validateBlob(req.Msg.EncryptedBlob, req.Msg.WrappedItemKey, req.Msg.TitleHash); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	kind, err := toModelKind(req.Msg.Kind)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	projectID, err := optionalUUID(req.Msg.ProjectId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	row, err := repo_entries.New(tx).UpdateEntry(ctx, repo_entries.UpdateEntryParams{
		ID:              id,
		UserID:          uc.UserID,
		ProjectID:       projectID,
		Kind:            kind,
		EncryptedBlob:   req.Msg.EncryptedBlob,
		WrappedItemKey:  req.Msg.WrappedItemKey,
		TitleHash:       req.Msg.TitleHash,
		DomainHash:      req.Msg.DomainHash,
		HasTotp:         req.Msg.HasTotp,
		IsFavorite:      req.Msg.IsFavorite,
		ExpectedVersion: int32(req.Msg.ExpectedVersion),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("entry missing or version mismatch"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	middleware.SetAuditTarget(ctx, row.ID)
	return connect.NewResponse(&pb.UpdateEntryResponse{Entry: toEntry(row)}), nil
}

// DeleteEntry physically removes the row. No tombstone — the ciphertext
// becomes immediately unreachable.
func (s *Service) DeleteEntry(ctx context.Context, req *connect.Request[pb.DeleteEntryRequest]) (*connect.Response[pb.DeleteEntryResponse], error) {
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid entry id"))
	}
	rows, err := repo_entries.New(tx).DeleteEntry(ctx, repo_entries.DeleteEntryParams{ID: id, UserID: uc.UserID})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if rows == 0 {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("entry not found"))
	}
	middleware.SetAuditTarget(ctx, id)
	return connect.NewResponse(&pb.DeleteEntryResponse{}), nil
}

// ToggleFavorite flips the is_favorite flag without touching the blob.
func (s *Service) ToggleFavorite(ctx context.Context, req *connect.Request[pb.ToggleFavoriteRequest]) (*connect.Response[pb.ToggleFavoriteResponse], error) {
	uc := middleware.MustFromContext(ctx)
	tx := middleware.MustTxFromContext(ctx)
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid entry id"))
	}
	row, err := repo_entries.New(tx).ToggleFavorite(ctx, repo_entries.ToggleFavoriteParams{
		ID:         id,
		UserID:     uc.UserID,
		IsFavorite: req.Msg.IsFavorite,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("entry not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&pb.ToggleFavoriteResponse{Entry: toEntry(row)}), nil
}

// --- conversion helpers ---

func toEntryMeta(r *models.Entry) *pb.EntryMeta {
	m := &pb.EntryMeta{
		Id:         r.ID.String(),
		Kind:       fromModelKind(r.Kind),
		TitleHash:  r.TitleHash,
		DomainHash: r.DomainHash,
		HasTotp:    r.HasTotp,
		IsFavorite: r.IsFavorite,
		Version:    uint32(r.Version),
		CreatedAt:  timestamppb.New(r.CreatedAt.Time),
		UpdatedAt:  timestamppb.New(r.UpdatedAt.Time),
	}
	if r.ProjectID.Valid {
		m.ProjectId = r.ProjectID.UUID.String()
	}
	return m
}

func toEntry(r *models.Entry) *pb.Entry {
	e := &pb.Entry{
		Id:             r.ID.String(),
		Kind:           fromModelKind(r.Kind),
		EncryptedBlob:  r.EncryptedBlob,
		WrappedItemKey: r.WrappedItemKey,
		TitleHash:      r.TitleHash,
		DomainHash:     r.DomainHash,
		HasTotp:        r.HasTotp,
		IsFavorite:     r.IsFavorite,
		Version:        uint32(r.Version),
		CreatedAt:      timestamppb.New(r.CreatedAt.Time),
		UpdatedAt:      timestamppb.New(r.UpdatedAt.Time),
	}
	if r.ProjectID.Valid {
		e.ProjectId = r.ProjectID.UUID.String()
	}
	return e
}

func buildListParams(userID uuid.UUID, msg *pb.ListEntriesRequest) (repo_entries.ListEntriesParams, error) {
	limit := int32(msg.Limit)
	if limit <= 0 {
		limit = defaultListLimit
	}
	if limit > maxListLimit {
		limit = maxListLimit
	}

	params := repo_entries.ListEntriesParams{
		UserID:    userID,
		PageLimit: limit,
	}
	if msg.ProjectId != nil {
		pid, err := uuid.Parse(*msg.ProjectId)
		if err != nil {
			return params, errors.New("invalid project_id")
		}
		params.ProjectID = uuid.NullUUID{UUID: pid, Valid: true}
	}
	if msg.Kind != nil {
		k, err := toModelKind(*msg.Kind)
		if err != nil {
			return params, err
		}
		params.Kind = repo_entries.NullEntryKind{EntryKind: k, Valid: true}
	}
	if len(msg.TitleHashes) > 0 {
		params.TitleHashes = msg.TitleHashes
	}
	if len(msg.DomainHashes) > 0 {
		params.DomainHashes = msg.DomainHashes
	}
	if msg.FavoritesOnly != nil {
		params.FavoritesOnly = pgtype.Bool{Bool: *msg.FavoritesOnly, Valid: true}
	}
	if msg.HasTotpOnly != nil {
		params.HasTotpOnly = pgtype.Bool{Bool: *msg.HasTotpOnly, Valid: true}
	}
	if msg.UpdatedAfter != nil {
		params.UpdatedAfter = pgtype.Timestamptz{Time: msg.UpdatedAfter.AsTime(), Valid: true}
	}
	return params, nil
}

func toModelKind(k pb.EntryKind) (models.EntryKind, error) {
	switch k {
	case pb.EntryKind_ENTRY_KIND_LOGIN:
		return models.EntryKindLogin, nil
	case pb.EntryKind_ENTRY_KIND_TOTP:
		return models.EntryKindTotp, nil
	case pb.EntryKind_ENTRY_KIND_CARD:
		return models.EntryKindCard, nil
	case pb.EntryKind_ENTRY_KIND_IDENTITY:
		return models.EntryKindIdentity, nil
	case pb.EntryKind_ENTRY_KIND_SSH_KEY:
		return models.EntryKindSshKey, nil
	case pb.EntryKind_ENTRY_KIND_NOTE:
		return models.EntryKindNote, nil
	default:
		return "", errors.New("unknown entry kind")
	}
}

func fromModelKind(k models.EntryKind) pb.EntryKind {
	switch k {
	case models.EntryKindLogin:
		return pb.EntryKind_ENTRY_KIND_LOGIN
	case models.EntryKindTotp:
		return pb.EntryKind_ENTRY_KIND_TOTP
	case models.EntryKindCard:
		return pb.EntryKind_ENTRY_KIND_CARD
	case models.EntryKindIdentity:
		return pb.EntryKind_ENTRY_KIND_IDENTITY
	case models.EntryKindSshKey:
		return pb.EntryKind_ENTRY_KIND_SSH_KEY
	case models.EntryKindNote:
		return pb.EntryKind_ENTRY_KIND_NOTE
	default:
		return pb.EntryKind_ENTRY_KIND_UNSPECIFIED
	}
}

func parseUUIDs(raws []string) ([]uuid.UUID, error) {
	out := make([]uuid.UUID, 0, len(raws))
	for _, r := range raws {
		id, err := uuid.Parse(r)
		if err != nil {
			return nil, errors.New("invalid id in batch")
		}
		out = append(out, id)
	}
	return out, nil
}

func optionalUUID(s *string) (uuid.NullUUID, error) {
	if s == nil || *s == "" {
		return uuid.NullUUID{}, nil
	}
	id, err := uuid.Parse(*s)
	if err != nil {
		return uuid.NullUUID{}, errors.New("invalid project_id")
	}
	return uuid.NullUUID{UUID: id, Valid: true}, nil
}

func validateBlob(blob, wrappedKey, titleHash []byte) error {
	if len(blob) < 29 {
		return errors.New("encrypted_blob too short")
	}
	if len(wrappedKey) < 29 {
		return errors.New("wrapped_item_key too short")
	}
	if len(titleHash) != 32 {
		return errors.New("title_hash must be SHA-256 (32 bytes)")
	}
	return nil
}

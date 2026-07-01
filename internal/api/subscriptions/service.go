// Package subscriptions implements the server-streaming endpoint that
// pushes change hints to the WebUI via Postgres LISTEN/NOTIFY.
//
// Notifications carry no secret material: just the kind of change and a
// server-side timestamp. Clients use them to invalidate TanStack Query
// caches and refetch; the regular query endpoints still do the work.
//
// Cross-instance fan-out: every server instance LISTENs the same per-user
// channel, so a NOTIFY published by an instance completing an EntriesService
// mutation reaches every connected client regardless of which instance
// terminates each SSE stream. See plan §17.4 — "polling → SSE".
package subscriptions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/sxwebdev/oblivio/internal/api/gen/go/oblivio/v1"
	"github.com/sxwebdev/oblivio/internal/api/gen/go/oblivio/v1/obliviov1connect"
	"github.com/sxwebdev/oblivio/internal/api/middleware"
)

// heartbeatInterval bounds how long a connected client waits between
// pushes when nothing is happening. Long-lived TCP connections through
// load balancers / browsers tend to time out without traffic; a periodic
// heartbeat keeps both sides aware of the link.
const heartbeatInterval = 25 * time.Second

// streamSlot is a per-stream token used as map value identity (function
// values cannot be compared reliably in Go). Each Subscribe allocates a
// new slot; release only clears the map entry if the slot still owns
// it.
type streamSlot struct {
	cancel context.CancelFunc
}

// streamRegistry tracks the currently-active SSE stream per user so a
// second Subscribe from the same user supersedes the first (H-4).
// Without this cap a single authenticated client can pin one pgxpool
// connection per concurrent tab and exhaust the pool — denying service
// to every other request including audit-chain writes.
type streamRegistry struct {
	mu     sync.Mutex
	active map[uuid.UUID]*streamSlot
}

func newStreamRegistry() *streamRegistry {
	return &streamRegistry{active: make(map[uuid.UUID]*streamSlot)}
}

// take installs slot as the active stream for userID, cancelling any
// previous stream registered under the same id. Returns the same slot
// for the caller to pass to release on stream exit.
func (r *streamRegistry) take(userID uuid.UUID, slot *streamSlot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if prev, ok := r.active[userID]; ok && prev != slot {
		prev.cancel()
	}
	r.active[userID] = slot
}

// release clears the registry entry only if the calling slot still owns
// it. If a newer Subscribe already took the slot, release is a no-op so
// the old stream's defer cannot evict the new one.
func (r *streamRegistry) release(userID uuid.UUID, slot *streamSlot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, ok := r.active[userID]; ok && cur == slot {
		delete(r.active, userID)
	}
}

// Service implements SubscriptionsService.
type Service struct {
	obliviov1connect.UnimplementedSubscriptionsServiceHandler
	pool     *pgxpool.Pool
	registry *streamRegistry
}

// NewService constructs a handler. The pool is used to dedicate one
// connection per active stream (LISTEN binds to a session).
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, registry: newStreamRegistry()}
}

// Subscribe opens a server stream and pushes notifications until the
// client cancels the context or the LISTEN connection drops.
//
// At most one Subscribe stream is allowed per user (H-4). A second
// concurrent Subscribe cancels the first; the first returns Aborted so
// the client can distinguish "we were evicted" from a network drop.
func (s *Service) Subscribe(
	ctx context.Context,
	_ *connect.Request[pb.SubscribeRequest],
	stream *connect.ServerStream[pb.SubscribeResponse],
) error {
	uc := middleware.MustFromContext(ctx)
	channel := ChannelName(uc.UserID)

	// Wrap the request context so we can be cancelled from the registry
	// when a newer Subscribe arrives. parentCtx (the original request
	// context) is retained so we can distinguish "client disconnected"
	// from "evicted by newer subscription".
	parentCtx := ctx
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	slot := &streamSlot{cancel: cancel}
	s.registry.take(uc.UserID, slot)
	defer s.registry.release(uc.UserID, slot)
	ctx = streamCtx

	// One LISTEN connection per stream. Acquire returns a connection
	// pinned to a single backend session — exactly what LISTEN requires.
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return connect.NewError(connect.CodeInternal, fmt.Errorf("acquire conn: %w", err))
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, fmt.Sprintf("LISTEN %s", quoteIdent(channel))); err != nil {
		return connect.NewError(connect.CodeInternal, fmt.Errorf("LISTEN: %w", err))
	}

	heartbeat := time.NewTicker(heartbeatInterval)
	defer heartbeat.Stop()

	for {
		// Race the heartbeat against an incoming notification by using a
		// context with the heartbeat interval as deadline; on timeout we
		// emit a heartbeat and continue. On notification we emit the
		// real event.
		waitCtx, cancel := context.WithTimeout(ctx, heartbeatInterval)
		notification, err := conn.Conn().WaitForNotification(waitCtx)
		cancel()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				if err := stream.Send(heartbeatResponse()); err != nil {
					return err
				}
				continue
			}
			if errors.Is(err, context.Canceled) {
				// Distinguish a client disconnect (parent ctx done) from
				// being evicted by a newer Subscribe (only streamCtx done).
				// The latter is a deliberate server-side action so the
				// client can show "subscription replaced by a newer tab".
				if parentCtx.Err() == nil {
					return connect.NewError(connect.CodeAborted, errors.New("subscription superseded"))
				}
				return nil
			}
			return connect.NewError(connect.CodeInternal, fmt.Errorf("WaitForNotification: %w", err))
		}
		resp, err := decodePayload(notification.Payload)
		if err != nil {
			// Malformed payload from a stale or misbehaving publisher —
			// log via the stream error path would be too loud; just skip.
			continue
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}

// ChannelName returns the LISTEN/NOTIFY channel a per-user subscription
// binds to. Exported so the publish-side helpers (entries, projects) can
// produce matching names without re-implementing the convention.
func ChannelName(userID uuid.UUID) string {
	// Postgres identifiers max 63 bytes — `oblivio_user_` (13) + UUID (36)
	// hex with dashes is 49 bytes total. Strip the dashes to stay well
	// under the cap and avoid quoting headaches.
	hex := userID.String()
	cleaned := make([]byte, 0, len(hex))
	for i := 0; i < len(hex); i++ {
		if hex[i] != '-' {
			cleaned = append(cleaned, hex[i])
		}
	}
	return "oblivio_user_" + string(cleaned)
}

// payload is what publishers serialise into pg_notify(). Adding fields is
// non-breaking; clients ignore unknowns.
type payload struct {
	Kind string `json:"k"`
}

const (
	kindEntries  = "entries"
	kindProjects = "projects"
)

// EncodeEntriesPayload returns the JSON publishers attach to a NOTIFY
// when entries change. Single helper so a typo in one publisher doesn't
// silently make every other publisher's events look different.
func EncodeEntriesPayload() string {
	b, _ := json.Marshal(payload{Kind: kindEntries})
	return string(b)
}

// EncodeProjectsPayload mirrors EncodeEntriesPayload for project changes.
func EncodeProjectsPayload() string {
	b, _ := json.Marshal(payload{Kind: kindProjects})
	return string(b)
}

func decodePayload(s string) (*pb.SubscribeResponse, error) {
	var p payload
	if err := json.Unmarshal([]byte(s), &p); err != nil {
		return nil, err
	}
	kind := pb.NotificationKind_NOTIFICATION_KIND_UNSPECIFIED
	switch p.Kind {
	case kindEntries:
		kind = pb.NotificationKind_NOTIFICATION_KIND_ENTRIES_UPDATED
	case kindProjects:
		kind = pb.NotificationKind_NOTIFICATION_KIND_PROJECTS_UPDATED
	}
	return &pb.SubscribeResponse{
		Notification: &pb.Notification{
			Kind: kind,
			At:   timestamppb.Now(),
		},
	}, nil
}

func heartbeatResponse() *pb.SubscribeResponse {
	return &pb.SubscribeResponse{
		Notification: &pb.Notification{
			Kind: pb.NotificationKind_NOTIFICATION_KIND_HEARTBEAT,
			At:   timestamppb.Now(),
		},
	}
}

// quoteIdent wraps a Postgres identifier in double-quotes and doubles any
// embedded quotes. Defensive — ChannelName output never contains a quote,
// but the LISTEN target is composed via Sprintf so we treat it as untrusted.
func quoteIdent(s string) string {
	out := make([]byte, 0, len(s)+2)
	out = append(out, '"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' {
			out = append(out, '"', '"')
		} else {
			out = append(out, s[i])
		}
	}
	out = append(out, '"')
	return string(out)
}

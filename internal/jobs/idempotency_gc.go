// idempotency_gc reaps expired idempotency_keys rows. Without periodic
// cleanup the table grows once per CreateProject/UpdateProject/etc., bound
// only by the 24h TTL.
package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/riverqueue/river"
	"github.com/tkcrm/mx/logger"

	"github.com/sxwebdev/oblivio/internal/store"
)

// IdempotencyGCArgs is the River JobArgs payload for the idempotency reaper.
type IdempotencyGCArgs struct{}

// Kind is the River-required identifier for this job.
func (IdempotencyGCArgs) Kind() string { return "idempotency_gc" }

// IdempotencyGCWorker deletes expired idempotency_keys rows.
type IdempotencyGCWorker struct {
	river.WorkerDefaults[IdempotencyGCArgs]
	st  *store.Store
	log logger.ExtendedLogger
}

// NewIdempotencyGCWorker constructs a worker.
func NewIdempotencyGCWorker(st *store.Store, log logger.ExtendedLogger) *IdempotencyGCWorker {
	return &IdempotencyGCWorker{st: st, log: log}
}

// Work executes one reap pass.
func (w *IdempotencyGCWorker) Work(ctx context.Context, _ *river.Job[IdempotencyGCArgs]) error {
	n, err := w.st.IdempotencyKeys().DeleteExpiredIdempotencyEntries(ctx)
	if err != nil {
		return fmt.Errorf("idempotency gc: %w", err)
	}
	if n > 0 {
		w.log.Infow("idempotency gc reaped", "rows", n)
	}
	return nil
}

// idempotencyGCInterval mirrors the other GC interval helpers — a typo in
// config can't pin the worker into a hot loop.
func idempotencyGCInterval(d time.Duration) time.Duration {
	const minInterval = time.Minute
	if d < minInterval {
		return time.Hour
	}
	return d
}

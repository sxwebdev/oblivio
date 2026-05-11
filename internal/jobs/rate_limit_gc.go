// rate_limit_gc reaps idle rate_limit_buckets rows. The DB function
// refills tokens lazily on every Allow() call, so a bucket whose
// refilled_at is older than ~1 hour has effectively returned to a full
// state — deleting it is identical to letting it persist.
package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/riverqueue/river"
	"github.com/tkcrm/mx/logger"

	"github.com/sxwebdev/oblivio/internal/store"
)

// RateLimitGCArgs is the River JobArgs payload.
type RateLimitGCArgs struct{}

// Kind is the River-required identifier for this job.
func (RateLimitGCArgs) Kind() string { return "rate_limit_gc" }

// RateLimitGCWorker deletes stale rate_limit_buckets rows.
type RateLimitGCWorker struct {
	river.WorkerDefaults[RateLimitGCArgs]
	st  *store.Store
	log logger.ExtendedLogger
}

// NewRateLimitGCWorker constructs a worker.
func NewRateLimitGCWorker(st *store.Store, log logger.ExtendedLogger) *RateLimitGCWorker {
	return &RateLimitGCWorker{st: st, log: log}
}

// Work executes one reap pass.
func (w *RateLimitGCWorker) Work(ctx context.Context, _ *river.Job[RateLimitGCArgs]) error {
	n, err := w.st.RateLimitBuckets().DeleteStaleRateLimitBuckets(ctx)
	if err != nil {
		return fmt.Errorf("rate-limit gc: %w", err)
	}
	if n > 0 {
		w.log.Infow("rate-limit gc reaped", "rows", n)
	}
	return nil
}

func rateLimitGCInterval(d time.Duration) time.Duration {
	const minInterval = time.Minute
	if d < minInterval {
		return time.Hour
	}
	return d
}

// recovery_gc reaps expired recovery_sessions rows. Same pattern as
// mfa_gc — abandoned recovery handshakes pile up until swept.
package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/riverqueue/river"
	"github.com/tkcrm/mx/logger"

	"github.com/sxwebdev/oblivio/internal/store"
)

// RecoveryGCArgs is the River JobArgs payload for the recovery reaper.
type RecoveryGCArgs struct{}

// Kind is the River-required identifier for this job.
func (RecoveryGCArgs) Kind() string { return "recovery_gc" }

// RecoveryGCWorker deletes expired recovery_sessions rows.
type RecoveryGCWorker struct {
	river.WorkerDefaults[RecoveryGCArgs]
	st  *store.Store
	log logger.ExtendedLogger
}

// NewRecoveryGCWorker constructs a worker.
func NewRecoveryGCWorker(st *store.Store, log logger.ExtendedLogger) *RecoveryGCWorker {
	return &RecoveryGCWorker{st: st, log: log}
}

// Work executes one reap pass.
func (w *RecoveryGCWorker) Work(ctx context.Context, _ *river.Job[RecoveryGCArgs]) error {
	n, err := w.st.RecoverySessions().DeleteExpiredRecoverySessions(ctx)
	if err != nil {
		return fmt.Errorf("recovery gc: %w", err)
	}
	if n > 0 {
		w.log.Infow("recovery gc reaped", "rows", n)
	}
	return nil
}

func recoveryGCInterval(d time.Duration) time.Duration {
	const minInterval = time.Minute
	if d < minInterval {
		return 5 * time.Minute
	}
	return d
}

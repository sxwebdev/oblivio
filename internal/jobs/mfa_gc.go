// mfa_gc reaps expired mfa_challenges rows. Once a challenge passes its
// 5-minute TTL the row is dead weight; the SQL DELETE...RETURNING in
// Take/Peek covers the consumed path, but never-completed challenges
// (user closed the tab, MFA prompt timed out) need a periodic sweep.
package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/riverqueue/river"
	"github.com/tkcrm/mx/logger"

	"github.com/sxwebdev/oblivio/internal/store"
)

// MFAGCArgs is the River JobArgs payload for the MFA reaper.
type MFAGCArgs struct{}

// Kind is the River-required identifier for this job.
func (MFAGCArgs) Kind() string { return "mfa_gc" }

// MFAGCWorker deletes expired mfa_challenges rows.
type MFAGCWorker struct {
	river.WorkerDefaults[MFAGCArgs]
	st  *store.Store
	log logger.ExtendedLogger
}

// NewMFAGCWorker constructs a worker.
func NewMFAGCWorker(st *store.Store, log logger.ExtendedLogger) *MFAGCWorker {
	return &MFAGCWorker{st: st, log: log}
}

// Work executes one reap pass.
func (w *MFAGCWorker) Work(ctx context.Context, _ *river.Job[MFAGCArgs]) error {
	n, err := w.st.MFAChallenges().DeleteExpiredMFAChallenges(ctx)
	if err != nil {
		return fmt.Errorf("mfa gc: %w", err)
	}
	if n > 0 {
		w.log.Infow("mfa gc reaped", "rows", n)
	}
	return nil
}

// mfaGCInterval clamps the configured interval so a typo can't pin the
// worker into a hot loop.
func mfaGCInterval(d time.Duration) time.Duration {
	const minInterval = time.Minute
	if d < minInterval {
		return 5 * time.Minute
	}
	return d
}

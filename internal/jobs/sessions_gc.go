// sessions_gc reaps stale rows from auth_sessions. A session becomes
// reapable once its refresh window has fully elapsed OR it has been
// revoked for long enough that the audit chain already captured the
// termination event. Active sessions and recently-revoked rows stay so
// the UI can still show "you signed out 10 min ago" attribution.
//
// The query is index-friendly: refresh_expires_at and revoked_at are
// timestamp-comparable scans that scale with the live set, not the
// historical one.
package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/riverqueue/river"
	"github.com/tkcrm/mx/logger"

	"github.com/sxwebdev/oblivio/internal/config"
	"github.com/sxwebdev/oblivio/internal/store"
)

// sessionsGCInterval reads the configured cadence and floors it to one
// minute so a typo in config.yaml cannot pin the worker into a hot loop.
func sessionsGCInterval(cfg config.JobsConfig) time.Duration {
	const minInterval = time.Minute
	if cfg.SessionsGCInterval < minInterval {
		return time.Hour
	}
	return cfg.SessionsGCInterval
}

// SessionsGCArgs is the River JobArgs payload for the session reaper.
type SessionsGCArgs struct{}

// Kind is the River-required identifier for this job.
func (SessionsGCArgs) Kind() string { return "sessions_gc" }

// SessionsGCWorker deletes stale auth_sessions rows on a fixed cadence.
type SessionsGCWorker struct {
	river.WorkerDefaults[SessionsGCArgs]
	st      *store.Store
	log     logger.ExtendedLogger
	retainD time.Duration
}

// NewSessionsGCWorker constructs a worker. retain is the grace period
// (24h matches the idempotency TTL and is plenty for "just clicked
// Logout" investigations).
func NewSessionsGCWorker(st *store.Store, log logger.ExtendedLogger) *SessionsGCWorker {
	return &SessionsGCWorker{st: st, log: log, retainD: 24 * time.Hour}
}

// Work executes one reap pass.
func (w *SessionsGCWorker) Work(ctx context.Context, _ *river.Job[SessionsGCArgs]) error {
	cutoff := pgtype.Timestamptz{Time: time.Now().Add(-w.retainD), Valid: true}
	n, err := w.st.AuthSessions().DeleteExpiredSessions(ctx, cutoff)
	if err != nil {
		return fmt.Errorf("sessions gc: %w", err)
	}
	if n > 0 {
		w.log.Infow("sessions gc reaped", "rows", n, "cutoff", cutoff.Time)
	}
	return nil
}

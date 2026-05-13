// auth_tokens_gc reaps expired rows from the PG-backed token store.
// Every CreateToken writes an expires_at timestamp; we collect anything
// already past that. Without this the table grows unbounded over months.
package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/riverqueue/river"
	"github.com/tkcrm/mx/logger"

	"github.com/sxwebdev/oblivio/internal/auth"
)

// AuthTokensGCArgs is the River JobArgs payload for the auth-tokens reaper.
type AuthTokensGCArgs struct{}

// Kind is the River-required identifier for this job.
func (AuthTokensGCArgs) Kind() string { return "auth_tokens_gc" }

// AuthTokensGCWorker deletes expired rows from auth_tokens.
type AuthTokensGCWorker struct {
	river.WorkerDefaults[AuthTokensGCArgs]
	store *auth.PGTokenStore
	log   logger.ExtendedLogger
}

// NewAuthTokensGCWorker constructs a worker.
func NewAuthTokensGCWorker(store *auth.PGTokenStore, log logger.ExtendedLogger) *AuthTokensGCWorker {
	return &AuthTokensGCWorker{store: store, log: log}
}

// Work executes one reap pass.
func (w *AuthTokensGCWorker) Work(ctx context.Context, _ *river.Job[AuthTokensGCArgs]) error {
	n, err := w.store.DeleteExpired(ctx)
	if err != nil {
		return fmt.Errorf("auth tokens gc: %w", err)
	}
	if n > 0 {
		w.log.Infow("auth tokens gc reaped", "rows", n)
	}
	return nil
}

// authTokensGCInterval mirrors sessionsGCInterval — a typo in config can't
// drop the worker into a hot loop.
func authTokensGCInterval(d time.Duration) time.Duration {
	const minInterval = time.Minute
	if d < minInterval {
		return time.Hour
	}
	return d
}

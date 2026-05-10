// audit_chain_verify schedules the periodic SHA-256 walk over the audit_log
// table. The verifier (internal/audit.Verifier) compares the running hash
// against system_state.audit_chain_head and emits a Prometheus counter +
// structured log line on every run. A mismatch is the canonical "someone
// edited the DB out-of-band" alarm and should page on-call.
package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/tkcrm/mx/logger"

	"github.com/sxwebdev/oblivio/internal/audit"
	"github.com/sxwebdev/oblivio/internal/metrics"
)

// AuditChainVerifyArgs is the River JobArgs payload for the verifier. The
// job carries no state — every run reads the chain head fresh from
// system_state.
type AuditChainVerifyArgs struct{}

// Kind is the River-required identifier for this job.
func (AuditChainVerifyArgs) Kind() string { return "audit_chain_verify" }

// AuditChainVerifyWorker is the River worker that drives the verifier.
type AuditChainVerifyWorker struct {
	river.WorkerDefaults[AuditChainVerifyArgs]
	pool *pgxpool.Pool
	log  logger.ExtendedLogger
}

// NewAuditChainVerifyWorker constructs a worker. The pool must outlive the
// worker (River shuts down workers before pool.Close on LIFO teardown).
func NewAuditChainVerifyWorker(pool *pgxpool.Pool, log logger.ExtendedLogger) *AuditChainVerifyWorker {
	return &AuditChainVerifyWorker{pool: pool, log: log}
}

// Work executes one verification pass. Returning a non-nil error puts the
// job back on the River retry queue with exponential backoff — that is
// fine for transient DB errors but pointless for genuine chain mismatch,
// which we therefore report as success-with-alarm (counter + log) rather
// than an error.
func (w *AuditChainVerifyWorker) Work(ctx context.Context, _ *river.Job[AuditChainVerifyArgs]) error {
	res, err := audit.NewVerifier(w.pool).Run(ctx)
	if err != nil {
		metrics.AuditChainVerifyRunsTotal.WithLabelValues("error").Inc()
		w.log.Errorw("audit chain verify failed", "error", err)
		return fmt.Errorf("audit verify: %w", err)
	}
	metrics.AuditChainHeight.Set(float64(res.Height))
	if res.OK() {
		metrics.AuditChainVerifyRunsTotal.WithLabelValues("ok").Inc()
		w.log.Infow("audit chain verify ok", "height", res.Height, "head", audit.HexHead(res.Head))
		return nil
	}
	metrics.AuditChainVerifyRunsTotal.WithLabelValues("mismatch").Inc()
	w.log.Errorw("audit chain MISMATCH — investigate",
		"height", res.Height,
		"stored_head", audit.HexHead(res.Head),
		"computed_head", audit.HexHead(res.Computed),
		"first_bad_id", res.FirstBadID,
	)
	return nil
}

// auditChainVerifySchedule returns the River schedule for the periodic
// verify run. Daily is the plan §11.1 default; we expose it as a function
// so tests can substitute a shorter interval.
func auditChainVerifySchedule() time.Duration { return 24 * time.Hour }

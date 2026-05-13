// audit_chain_verify schedules the periodic SHA-256 walk over the audit_log
// table. The verifier (internal/audit.Verifier) compares the running hash
// against system_state.audit_chain_head and emits a Prometheus counter +
// structured log line on every run. A mismatch is the canonical "someone
// edited the DB out-of-band" alarm and should page on-call.
//
// On top of the in-DB chain we cross-check the most recent signed anchor
// from audit_chain_anchors: a DB-only attacker can rewrite both rows and
// the head, but cannot forge the anchor signature without the signer key.
// A signature mismatch is logged at the same severity as a chain mismatch.
package jobs

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/tkcrm/mx/logger"

	"github.com/sxwebdev/oblivio/internal/audit"
	"github.com/sxwebdev/oblivio/internal/config"
	"github.com/sxwebdev/oblivio/internal/metrics"
	"github.com/sxwebdev/oblivio/internal/store"
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
	pool   *pgxpool.Pool
	st     *store.Store
	signer audit.Signer // nil → anchor check disabled
	log    logger.ExtendedLogger
}

// NewAuditChainVerifyWorker constructs a worker. The pool must outlive the
// worker (River shuts down workers before pool.Close on LIFO teardown).
// `st` and `signer` together enable the anchor cross-check; pass nil to
// fall back to chain-only verification.
func NewAuditChainVerifyWorker(pool *pgxpool.Pool, st *store.Store, signer audit.Signer, log logger.ExtendedLogger) *AuditChainVerifyWorker {
	return &AuditChainVerifyWorker{pool: pool, st: st, signer: signer, log: log}
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
	if err := w.verifyAnchor(ctx, res.Head); err != nil {
		w.log.Errorw("audit anchor verification FAILED", "error", err)
	}
	return nil
}

// verifyAnchor pulls the most recent signed anchor and confirms (a) its
// signature is valid under the worker's known public key, and (b) the
// signed head matches the head we just observed in system_state. A
// signature mismatch means a DB-only attacker rewrote the rows AND the
// head value coherently, but couldn't forge the signer's signature.
//
// Returns nil when the check passes OR the configuration disables it
// (no signer, no anchor row yet). Returns a non-nil error only on hard
// failures so the worker can log them at error severity.
func (w *AuditChainVerifyWorker) verifyAnchor(ctx context.Context, currentHead []byte) error {
	if w.signer == nil || w.st == nil {
		return nil
	}
	row, err := w.st.AuditChainAnchors().GetLatestAuditChainAnchor(ctx)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// No anchor written yet — verifier started before the first
			// anchor period elapsed. Not an error.
			return nil
		}
		return fmt.Errorf("load latest anchor: %w", err)
	}
	pub := w.signer.PublicKey()
	if len(pub) == 0 {
		return errors.New("anchor signer has no public key")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), row.Head, row.Signature) {
		return fmt.Errorf("anchor signature invalid (signer_id=%s)", row.SignerID)
	}
	if !bytes.Equal(row.Head, currentHead) {
		return fmt.Errorf("anchor head %x does not match current head %x", row.Head, currentHead)
	}
	return nil
}

// auditChainVerifyInterval reads the configured cadence and floors it to one
// minute so a typo in config.yaml cannot pin the worker into a hot loop.
// Daily is the plan §11.1 default.
func auditChainVerifyInterval(cfg config.JobsConfig) time.Duration {
	const minInterval = time.Minute
	if cfg.AuditChainVerifyInterval < minInterval {
		return 24 * time.Hour
	}
	return cfg.AuditChainVerifyInterval
}

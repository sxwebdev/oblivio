// audit_chain_anchor periodically signs the current audit_chain_head and
// stores the signature in audit_chain_anchors. The verifier in
// audit_chain_verify compares the head it walks the chain with the most
// recently anchored value; mismatch implies post-hoc tampering by an
// attacker with DB access (plan §17.4).
package jobs

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/tkcrm/mx/logger"

	"github.com/sxwebdev/oblivio/internal/audit"
	"github.com/sxwebdev/oblivio/internal/store"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_audit_chain_anchors"
)

// AuditChainAnchorArgs is the River JobArgs payload.
type AuditChainAnchorArgs struct{}

// Kind is the River-required identifier for this job.
func (AuditChainAnchorArgs) Kind() string { return "audit_chain_anchor" }

// AuditChainAnchorWorker signs the current head and writes an anchor row.
type AuditChainAnchorWorker struct {
	river.WorkerDefaults[AuditChainAnchorArgs]
	st     *store.Store
	pool   *pgxpool.Pool
	signer audit.Signer
	log    logger.ExtendedLogger
}

// NewAuditChainAnchorWorker constructs the worker. A nil signer disables the
// worker — it just logs and returns nil so the job queue stays healthy in
// deployments that haven't yet wired Vault transit or local Ed25519.
func NewAuditChainAnchorWorker(st *store.Store, pool *pgxpool.Pool, signer audit.Signer, log logger.ExtendedLogger) *AuditChainAnchorWorker {
	return &AuditChainAnchorWorker{st: st, pool: pool, signer: signer, log: log}
}

// Work loads the head, signs it, persists. The head read is done in its
// own short transaction with the RLS bypass GUC set — same pattern as
// audit.Append.
func (w *AuditChainAnchorWorker) Work(ctx context.Context, _ *river.Job[AuditChainAnchorArgs]) error {
	if w.signer == nil {
		w.log.Debugw("audit anchor: signer not configured, skipping")
		return nil
	}

	head, err := loadAuditHead(ctx, w.pool)
	if err != nil {
		return fmt.Errorf("audit anchor: load head: %w", err)
	}
	sig, signerID, err := w.signer.Sign(ctx, head)
	if err != nil {
		return fmt.Errorf("audit anchor: sign: %w", err)
	}
	if _, err := w.st.AuditChainAnchors().InsertAuditChainAnchor(ctx, repo_audit_chain_anchors.InsertAuditChainAnchorParams{
		Head:      head,
		Signature: sig,
		SignerID:  signerID,
	}); err != nil {
		return fmt.Errorf("audit anchor: insert: %w", err)
	}
	w.log.Infow("audit anchor written", "signer", signerID)
	return nil
}

// loadAuditHead reads the canonical head value out of system_state under a
// short transaction with RLS bypass. The format is JSON-quoted hex
// (see migration 004 + internal/audit/chain.go).
func loadAuditHead(ctx context.Context, pool *pgxpool.Pool) ([]byte, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SET LOCAL app.bypass_rls = 'true'"); err != nil {
		return nil, err
	}
	var raw []byte
	if err := tx.QueryRow(ctx,
		`SELECT value FROM system_state WHERE key = 'audit_chain_head'`,
	).Scan(&raw); err != nil {
		return nil, err
	}
	// JSON-encoded hex string. Strip the surrounding quotes via json.Unmarshal
	// rather than slicing, so a hand-edited value with whitespace still
	// decodes correctly.
	var hexStr string
	if err := json.Unmarshal(raw, &hexStr); err != nil {
		return nil, fmt.Errorf("audit anchor: unmarshal head: %w", err)
	}
	if hexStr == "" {
		return nil, errors.New("audit anchor: empty head")
	}
	return hex.DecodeString(hexStr)
}

// auditChainAnchorInterval clamps the configured interval so a typo can't
// pin the worker into a hot loop.
func auditChainAnchorInterval(d time.Duration) time.Duration {
	const minInterval = time.Minute
	if d < minInterval {
		return time.Hour
	}
	return d
}

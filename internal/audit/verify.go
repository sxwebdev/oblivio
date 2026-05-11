package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sxwebdev/oblivio/internal/models"
)

// VerifyResult summarises a single chain walk.
type VerifyResult struct {
	// Height is the id of the last row in the chain. Zero when the chain
	// is still empty (no events written yet).
	Height int64
	// Head is the SHA-256 stored in system_state.audit_chain_head.
	Head []byte
	// Computed is the running hash after re-applying every row.
	Computed []byte
	// FirstBadID is the smallest id whose computed self_hash differs from
	// the stored value. Zero when the chain is clean.
	FirstBadID int64
}

// OK reports a clean chain: head equals computed AND no row mismatched.
func (r VerifyResult) OK() bool {
	if r.FirstBadID != 0 {
		return false
	}
	return hashesEqual(r.Head, r.Computed)
}

// Verifier walks the audit chain from genesis and detects tampering.
// Construction is allocation-free; the heavy lifting happens in Run.
type Verifier struct {
	pool      *pgxpool.Pool
	batchSize int32
}

// NewVerifier builds a Verifier. batchSize is the number of rows pulled
// per query — 1024 strikes a reasonable memory/io balance for an audit
// log a typical user accumulates over years.
func NewVerifier(pool *pgxpool.Pool) *Verifier {
	return &Verifier{pool: pool, batchSize: 1024}
}

// Run replays the chain from the genesis entry (id=0 seed of 32 zero bytes)
// and returns a VerifyResult describing the state at completion.
//
// All reads happen inside a single transaction with the system bypass GUC
// set so RLS doesn't filter audit_log rows down to whichever user_id the
// session might have remembered.
//
// The verifier is read-only. Detection of a mismatch does not auto-remediate
// — callers should alarm/page on r.OK() == false. (Reconciliation requires
// human review: tampering could have happened in any of (DB,backup,replica).)
func (v *Verifier) Run(ctx context.Context) (VerifyResult, error) {
	tx, err := v.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return VerifyResult{}, fmt.Errorf("verify: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SET LOCAL app.bypass_rls = 'true'"); err != nil {
		return VerifyResult{}, fmt.Errorf("verify: set bypass: %w", err)
	}

	head, err := v.loadHeadTx(ctx, tx)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("load head: %w", err)
	}

	prev := genesisHash()
	var lastID int64
	var firstBad int64

	for {
		select {
		case <-ctx.Done():
			return VerifyResult{}, ctx.Err()
		default:
		}

		rows, err := v.fetchBatchTx(ctx, tx, lastID)
		if err != nil {
			return VerifyResult{}, err
		}
		if len(rows) == 0 {
			break
		}
		for _, row := range rows {
			expected := computeSelfHash(prev, row)
			if !hashesEqual(expected, row.SelfHash) && firstBad == 0 {
				firstBad = row.ID
			}
			if !hashesEqual(prev, row.PrevHash) && firstBad == 0 {
				firstBad = row.ID
			}
			prev = row.SelfHash
			lastID = row.ID
		}
	}

	return VerifyResult{
		Height:     lastID,
		Head:       head,
		Computed:   prev,
		FirstBadID: firstBad,
	}, nil
}

func (v *Verifier) loadHeadTx(ctx context.Context, tx pgx.Tx) ([]byte, error) {
	var raw []byte
	if err := tx.QueryRow(ctx,
		`SELECT value FROM system_state WHERE key = $1`,
		systemKeyChainHead,
	).Scan(&raw); err != nil {
		return nil, err
	}
	return decodeHashHexJSON(raw)
}

// fetchBatchTx pulls a window of rows by id with a hard ORDER BY id ASC.
// Runs inside the verify transaction so the system bypass GUC applies.
func (v *Verifier) fetchBatchTx(ctx context.Context, tx pgx.Tx, fromID int64) ([]*models.AuditLog, error) {
	rows, err := tx.Query(ctx,
		`SELECT id, user_id, action, target_id, ip, user_agent, metadata, prev_hash, self_hash, created_at
         FROM audit_log
         WHERE id > $1
         ORDER BY id ASC
         LIMIT $2`,
		fromID, v.batchSize,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.AuditLog
	for rows.Next() {
		var r models.AuditLog
		var ip *netip.Addr
		if err := rows.Scan(&r.ID, &r.UserID, &r.Action, &r.TargetID, &ip, &r.UserAgent, &r.Metadata, &r.PrevHash, &r.SelfHash, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.Ip = ip
		out = append(out, &r)
	}
	return out, rows.Err()
}

// computeSelfHash re-derives self_hash for a row from prev_hash and the
// canonicalised payload. It mirrors Writer.Append step for step.
func computeSelfHash(prev []byte, row *models.AuditLog) []byte {
	ev := Event{
		Action: row.Action,
	}
	if row.UserAgent.Valid {
		ev.UserAgent = row.UserAgent.String
	}
	if row.UserID.Valid {
		ev.UserID = uuid.NullUUID{UUID: row.UserID.UUID, Valid: true}
	}
	if row.TargetID.Valid {
		ev.TargetID = uuid.NullUUID{UUID: row.TargetID.UUID, Valid: true}
	}
	if row.Ip != nil {
		ev.IP = row.Ip
	}
	// Metadata persisted as JSONB; decode into the canonical map form so
	// canonicalRow sees the same structure the writer fed in.
	if len(row.Metadata) > 0 && !isJSONNull(row.Metadata) {
		var meta map[string]any
		if err := json.Unmarshal(row.Metadata, &meta); err == nil {
			ev.Metadata = meta
		}
	}
	canonical, err := canonicalRow(ev, rowCreatedAt(row))
	if err != nil {
		return nil
	}
	h := sha256.Sum256(append(append([]byte{}, prev...), canonical...))
	return h[:]
}

func rowCreatedAt(r *models.AuditLog) time.Time {
	if !r.CreatedAt.Valid {
		return time.Time{}
	}
	return r.CreatedAt.Time.UTC().Truncate(time.Microsecond)
}

func genesisHash() []byte { return make([]byte, 32) }

func hashesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isJSONNull(b []byte) bool { return bytes.Equal(b, []byte("null")) }

// ErrChainMismatch is returned by Verifier when the chain fails to match
// its stored head. Use errors.Is for behaviour-based checks.
var ErrChainMismatch = errors.New("audit chain mismatch")

// HexHead formats the leading bytes of a hash as hex — handy for logs.
func HexHead(b []byte) string {
	if len(b) > 8 {
		b = b[:8]
	}
	return hex.EncodeToString(b)
}

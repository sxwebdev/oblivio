// Package audit implements the append-only, hash-chained audit log.
//
// Every mutation in the system emits an Event that is hashed against the
// previous chain head and written transactionally together with the new
// head. A periodic verify job (Sprint 4) re-walks the chain and alarms on
// mismatch, which detects either tampering or replication divergence.
//
// The chain head lives in system_state.audit_chain_head as a hex-encoded
// 32-byte SHA-256 digest. Genesis = 32 zero bytes (seeded by migration 004).
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sxwebdev/oblivio/internal/models"
)

const systemKeyChainHead = "audit_chain_head"

// Event is the user-visible payload of an audit entry. Everything that goes
// into the SHA-256 chain is contained here (plus the prev_hash byte string).
type Event struct {
	UserID    uuid.NullUUID
	Action    models.AuditAction
	TargetID  uuid.NullUUID
	IP        *netip.Addr
	UserAgent string
	// Metadata is an opaque, application-defined JSON object. The writer
	// canonicalises it (sorted top-level keys) before hashing so that
	// re-serialisation yields identical bytes.
	Metadata map[string]any
}

// Writer appends events to the audit log under a serialised lock on the
// chain head. It must be the only path that writes to audit_log in
// production code (other than recovery tooling).
type Writer struct {
	pool *pgxpool.Pool
}

// NewWriter constructs a Writer bound to a pgx pool.
func NewWriter(pool *pgxpool.Pool) *Writer { return &Writer{pool: pool} }

// Append serialises a new event into the chain. It opens a short
// transaction that takes a row-level lock on system_state to prevent
// concurrent appends from racing on prev_hash.
func (w *Writer) Append(ctx context.Context, ev Event) (*models.AuditLog, error) {
	tx, err := w.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("audit: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var headRaw []byte
	if err := tx.QueryRow(ctx,
		`SELECT value FROM system_state WHERE key = $1 FOR UPDATE`,
		systemKeyChainHead,
	).Scan(&headRaw); err != nil {
		return nil, fmt.Errorf("audit: load head: %w", err)
	}
	prev, err := decodeHashHexJSON(headRaw)
	if err != nil {
		return nil, fmt.Errorf("audit: decode head: %w", err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	canonical, err := canonicalRow(ev, now)
	if err != nil {
		return nil, fmt.Errorf("audit: canonical row: %w", err)
	}
	self := sha256.Sum256(append(append([]byte{}, prev...), canonical...))

	row := &models.AuditLog{
		UserID:    ev.UserID,
		Action:    ev.Action,
		TargetID:  ev.TargetID,
		Ip:        ev.IP,
		UserAgent: pgtypeTextFrom(ev.UserAgent),
		Metadata:  metadataBytes(ev.Metadata),
		PrevHash:  prev,
		SelfHash:  self[:],
		CreatedAt: pgtype.Timestamptz{Time: now, Valid: true},
	}

	if err := tx.QueryRow(ctx, `
        INSERT INTO audit_log (user_id, action, target_id, ip, user_agent, metadata, prev_hash, self_hash, created_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
        RETURNING id`,
		row.UserID, row.Action, row.TargetID, row.Ip, row.UserAgent, row.Metadata,
		row.PrevHash, row.SelfHash, row.CreatedAt,
	).Scan(&row.ID); err != nil {
		return nil, fmt.Errorf("audit: insert: %w", err)
	}

	newHead, err := json.Marshal(hex.EncodeToString(self[:]))
	if err != nil {
		return nil, fmt.Errorf("audit: marshal head: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE system_state SET value = $1::jsonb, updated_at = now() WHERE key = $2`,
		newHead, systemKeyChainHead,
	); err != nil {
		return nil, fmt.Errorf("audit: update head: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("audit: commit: %w", err)
	}
	return row, nil
}

// canonicalRow returns a stable byte representation of an audit row for
// hashing. The field order is fixed in code and must NEVER change without
// a documented protocol-version bump.
func canonicalRow(ev Event, ts time.Time) ([]byte, error) {
	var ip string
	if ev.IP != nil {
		ip = ev.IP.String()
	}
	var target string
	if ev.TargetID.Valid {
		target = ev.TargetID.UUID.String()
	}
	var user string
	if ev.UserID.Valid {
		user = ev.UserID.UUID.String()
	}
	meta, err := canonicalJSON(ev.Metadata)
	if err != nil {
		return nil, err
	}
	// Stable schema: keys are emitted in fixed lexicographic order.
	// Changing this layout invalidates every existing chain entry, so we
	// keep it explicit and short.
	doc := canonicalDoc{
		Action:    string(ev.Action),
		CreatedAt: ts.UnixMicro(),
		IP:        ip,
		Metadata:  json.RawMessage(meta),
		TargetID:  target,
		UserAgent: ev.UserAgent,
		UserID:    user,
	}
	return json.Marshal(doc)
}

// canonicalDoc fixes the field order of the canonical hash payload. Go's
// encoding/json emits struct fields in declaration order, so this layout
// is deterministic across runs and Go versions.
type canonicalDoc struct {
	Action    string          `json:"action"`
	CreatedAt int64           `json:"created_at"`
	IP        string          `json:"ip"`
	Metadata  json.RawMessage `json:"metadata"`
	TargetID  string          `json:"target_id"`
	UserAgent string          `json:"user_agent"`
	UserID    string          `json:"user_id"`
}

// canonicalJSON serialises an arbitrary map with keys in sorted order. nil
// input becomes JSON null so the canonical form is well-defined.
func canonicalJSON(m map[string]any) ([]byte, error) {
	if m == nil {
		return []byte("null"), nil
	}
	return marshalSorted(m)
}

func marshalSorted(v any) ([]byte, error) {
	// json.Marshal does not sort map keys deterministically across runs in
	// the general case (it does for map[string]X since Go 1.12, but values
	// may themselves be unsorted maps). We re-encode to enforce order.
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var canonical any
	if err := json.Unmarshal(raw, &canonical); err != nil {
		return nil, err
	}
	return encodeSorted(canonical)
}

func encodeSorted(v any) ([]byte, error) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sortStrings(keys)
		buf := []byte{'{'}
		for i, k := range keys {
			if i > 0 {
				buf = append(buf, ',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return nil, err
			}
			buf = append(buf, kb...)
			buf = append(buf, ':')
			vb, err := encodeSorted(t[k])
			if err != nil {
				return nil, err
			}
			buf = append(buf, vb...)
		}
		buf = append(buf, '}')
		return buf, nil
	case []any:
		buf := []byte{'['}
		for i, e := range t {
			if i > 0 {
				buf = append(buf, ',')
			}
			vb, err := encodeSorted(e)
			if err != nil {
				return nil, err
			}
			buf = append(buf, vb...)
		}
		buf = append(buf, ']')
		return buf, nil
	default:
		return json.Marshal(v)
	}
}

// sortStrings is a small wrapper so we avoid pulling `sort` into the
// public surface tests; the cost is negligible at audit-row scale.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

func decodeHashHexJSON(raw []byte) ([]byte, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	if s == "" {
		return make([]byte, 32), nil
	}
	return hex.DecodeString(s)
}

func metadataBytes(m map[string]any) []byte {
	if m == nil {
		return []byte("{}")
	}
	b, _ := canonicalJSON(m)
	return b
}

func pgtypeTextFrom(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}

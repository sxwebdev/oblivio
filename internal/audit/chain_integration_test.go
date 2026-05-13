//go:build integration

package audit_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/google/uuid"

	"github.com/sxwebdev/oblivio/internal/audit"
	"github.com/sxwebdev/oblivio/internal/models"
	"github.com/sxwebdev/oblivio/internal/testutil"
)

func TestAuditChain_AppendAndVerify(t *testing.T) {
	pg := testutil.NewPostgres(t)
	ctx := context.Background()

	w := audit.NewWriter(pg.Pool)
	v := audit.NewVerifier(pg.Pool)

	ip := netip.MustParseAddr("203.0.113.1")
	for i := 0; i < 10; i++ {
		if _, err := w.Append(ctx, audit.Event{
			Action:    models.AuditAction("login"),
			UserID:    uuid.NullUUID{UUID: uuid.New(), Valid: true},
			IP:        &ip,
			UserAgent: "tester",
			Metadata:  map[string]any{"i": i, "reason": "test"},
		}); err != nil {
			t.Fatalf("append #%d: %v", i, err)
		}
	}

	res, err := v.Run(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK() {
		t.Fatalf("clean chain failed verify: firstBad=%d head=%x computed=%x",
			res.FirstBadID, res.Head, res.Computed)
	}
	if res.Height != 10 {
		t.Fatalf("height=%d, want 10", res.Height)
	}
}

func TestAuditChain_TamperDetected(t *testing.T) {
	pg := testutil.NewPostgres(t)
	ctx := context.Background()
	w := audit.NewWriter(pg.Pool)
	v := audit.NewVerifier(pg.Pool)

	for i := 0; i < 5; i++ {
		if _, err := w.Append(ctx, audit.Event{
			Action:   models.AuditAction("login"),
			Metadata: map[string]any{"i": i},
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Tamper: flip user_agent on the middle row.
	if _, err := pg.Pool.Exec(ctx,
		`UPDATE audit_log SET user_agent = 'TAMPERED' WHERE id = (SELECT id FROM audit_log ORDER BY id ASC OFFSET 2 LIMIT 1)`,
	); err != nil {
		t.Fatal(err)
	}

	res, err := v.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("verifier accepted a tampered chain")
	}
	if res.FirstBadID == 0 {
		t.Fatal("FirstBadID must point at the corrupted row")
	}
}

func TestAuditChain_DeletedRowDetected(t *testing.T) {
	pg := testutil.NewPostgres(t)
	ctx := context.Background()
	w := audit.NewWriter(pg.Pool)
	v := audit.NewVerifier(pg.Pool)

	for i := 0; i < 4; i++ {
		if _, err := w.Append(ctx, audit.Event{
			Action: models.AuditAction("login"),
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Drop the second row.
	if _, err := pg.Pool.Exec(ctx,
		`DELETE FROM audit_log WHERE id = (SELECT id FROM audit_log ORDER BY id ASC OFFSET 1 LIMIT 1)`,
	); err != nil {
		t.Fatal(err)
	}
	res, err := v.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("verifier accepted a chain with a missing link")
	}
}

func TestAuditChain_HeadAdvancesPerAppend(t *testing.T) {
	pg := testutil.NewPostgres(t)
	ctx := context.Background()
	w := audit.NewWriter(pg.Pool)

	var prevHead string
	for i := 0; i < 3; i++ {
		if _, err := w.Append(ctx, audit.Event{Action: models.AuditAction("login")}); err != nil {
			t.Fatal(err)
		}
		var head string
		if err := pg.Pool.QueryRow(ctx,
			`SELECT value::text FROM system_state WHERE key = 'audit_chain_head'`,
		).Scan(&head); err != nil {
			t.Fatal(err)
		}
		if i > 0 && head == prevHead {
			t.Fatal("head did not advance after append")
		}
		prevHead = head
	}
}

//go:build integration

package store_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/sxwebdev/oblivio/internal/testutil"
)

// TestRLS_ProjectsIsolation: user A and user B each create a project; a
// query running as user A cannot read B's project, even by guessing its id.
func TestRLS_ProjectsIsolation(t *testing.T) {
	pg := testutil.NewPostgres(t)
	ctx := context.Background()

	// Use a non-superuser role so RLS actually applies (superuser bypasses
	// RLS). The default container user is the DB owner / superuser, so we
	// have to create a fresh role for these checks.
	if _, err := pg.Pool.Exec(ctx, `CREATE ROLE app_rls NOLOGIN`); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.Pool.Exec(ctx, `GRANT USAGE ON SCHEMA public TO app_rls`); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.Pool.Exec(ctx, `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_rls`); err != nil {
		t.Fatal(err)
	}

	uidA := mustInsertUser(t, pg.Pool, "a@example.com")
	uidB := mustInsertUser(t, pg.Pool, "b@example.com")

	// Insert one project per user as superuser so we have ground truth.
	pidA := mustInsertProject(t, pg.Pool, uidA, "blob-a")
	pidB := mustInsertProject(t, pg.Pool, uidB, "blob-b")

	// Run cross-user reads as the restricted role with the GUC set to A.
	tx, err := pg.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE app_rls`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('app.current_user_id', $1, true)`, uidA.String()); err != nil {
		t.Fatal(err)
	}

	var count int
	// 1. User A sees its own project.
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM projects WHERE id = $1`, pidA).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("user A cannot see its own project (count=%d)", count)
	}

	// 2. User A cannot see user B's project even when given the exact id.
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM projects WHERE id = $1`, pidB).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("RLS leak: user A sees user B's project (count=%d)", count)
	}

	// 3. User A cannot DELETE user B's project (RLS check on WHERE applies).
	res, err := tx.Exec(ctx, `DELETE FROM projects WHERE id = $1`, pidB)
	if err != nil {
		t.Fatal(err)
	}
	if res.RowsAffected() != 0 {
		t.Fatalf("RLS leak: user A deleted user B's project (rows=%d)", res.RowsAffected())
	}
}

func TestRLS_DropsWhenGUCMissing(t *testing.T) {
	pg := testutil.NewPostgres(t)
	ctx := context.Background()

	if _, err := pg.Pool.Exec(ctx, `CREATE ROLE app_rls2 NOLOGIN`); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.Pool.Exec(ctx, `GRANT USAGE ON SCHEMA public TO app_rls2`); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.Pool.Exec(ctx, `GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_rls2`); err != nil {
		t.Fatal(err)
	}

	uid := mustInsertUser(t, pg.Pool, "c@example.com")
	mustInsertProject(t, pg.Pool, uid, "blob-c")

	tx, err := pg.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE app_rls2`); err != nil {
		t.Fatal(err)
	}
	// Intentionally do NOT set app.current_user_id.

	var count int
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM projects`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("RLS leak when GUC unset: count=%d (want 0)", count)
	}
}

func mustInsertUser(t *testing.T, p interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, email string,
) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := p.QueryRow(context.Background(),
		`INSERT INTO users (email) VALUES ($1) RETURNING id`, email,
	).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func mustInsertProject(t *testing.T, p interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, userID uuid.UUID, blob string,
) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := p.QueryRow(context.Background(),
		`INSERT INTO projects (user_id, encrypted_blob, wrapped_item_key, name_hash)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		userID, []byte(blob), []byte("wrap-"+blob), []byte("hash-"+blob),
	).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

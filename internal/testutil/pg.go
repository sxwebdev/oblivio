// Package testutil is the harness for integration tests that need a real
// Postgres. It spins up a fresh container per call to NewPostgres, runs
// every embedded migration, and returns a ready pgxpool. Callers are
// expected to defer Close — that tears down both the pool and the container.
//
// Tests gated on Docker should call Skip via SkipIfNoDocker (or set
// OBLIVIO_SKIP_INTEGRATION=1 to bypass entirely). In CI we keep both knobs
// — SkipIfNoDocker for laptops without Docker, the env knob for
// emergency-stop.
package testutil

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"
	tcpg "github.com/testcontainers/testcontainers-go/modules/postgres"

	sqlpkg "github.com/sxwebdev/oblivio/sql"
)

// PG is a live, migrated Postgres instance reachable via Pool.
type PG struct {
	Pool      *pgxpool.Pool
	DSN       string
	container *tcpg.PostgresContainer
}

// SkipIfNoDocker bails the test out cleanly when Docker isn't available or
// the user opted out via OBLIVIO_SKIP_INTEGRATION=1.
func SkipIfNoDocker(t *testing.T) {
	t.Helper()
	if os.Getenv("OBLIVIO_SKIP_INTEGRATION") != "" {
		t.Skip("OBLIVIO_SKIP_INTEGRATION set")
	}
	// testcontainers-go's reaper probes the docker daemon at module init —
	// if it can't, the first New() call fails. We pre-probe by looking for
	// the unix socket / DOCKER_HOST so we can skip more cleanly.
	if os.Getenv("DOCKER_HOST") == "" {
		if _, err := os.Stat("/var/run/docker.sock"); err != nil {
			t.Skip("docker not available — skipping integration test")
		}
	}
}

// NewPostgres starts a fresh Postgres container, runs all embedded
// migrations, and returns the ready pool. The lifetime is bound to the
// test: pg.Close() is registered via t.Cleanup.
func NewPostgres(t *testing.T) *PG {
	t.Helper()
	SkipIfNoDocker(t)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	pgC, err := tcpg.Run(ctx,
		"postgres:18-alpine",
		tcpg.WithDatabase("oblivio_test"),
		tcpg.WithUsername("oblivio"),
		tcpg.WithPassword("oblivio"),
		tcpg.BasicWaitStrategies(),
		tcpg.WithSQLDriver("pgx"),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}

	dsn, err := pgC.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = pgC.Terminate(ctx)
		t.Fatalf("connstring: %v", err)
	}

	if err := runMigrations(dsn); err != nil {
		_ = pgC.Terminate(ctx)
		t.Fatalf("migrate: %v", err)
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		_ = pgC.Terminate(ctx)
		t.Fatalf("pgxpool: %v", err)
	}

	pg := &PG{Pool: pool, DSN: dsn, container: pgC}
	t.Cleanup(pg.Close)
	return pg
}

// Close tears down the pool and the container. Idempotent.
func (p *PG) Close() {
	if p == nil {
		return
	}
	if p.Pool != nil {
		p.Pool.Close()
		p.Pool = nil
	}
	if p.container != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = p.container.Terminate(ctx)
		p.container = nil
	}
}

// Reset wipes user-scoped tables so a single container can be reused across
// sub-tests without a full restart. It does not touch system_state.
func (p *PG) Reset(ctx context.Context, t *testing.T) {
	t.Helper()
	tables := []string{
		"webauthn_credentials",
		"audit_log",
		"idempotency_keys",
		"rate_limit_buckets",
		"mfa_challenges",
		"recovery_sessions",
		"entries",
		"projects",
		"auth_sessions",
		"user_login_totp",
		"user_kdf_params",
		"user_vault",
		"user_auth",
		"users",
	}
	for _, tbl := range tables {
		if _, err := p.Pool.Exec(ctx, fmt.Sprintf("TRUNCATE TABLE %s RESTART IDENTITY CASCADE", tbl)); err != nil {
			t.Fatalf("truncate %s: %v", tbl, err)
		}
	}
	// Reset audit chain head to its genesis value.
	if _, err := p.Pool.Exec(ctx,
		`UPDATE system_state SET value = '"0000000000000000000000000000000000000000000000000000000000000000"'::jsonb WHERE key = 'audit_chain_head'`,
	); err != nil {
		t.Fatalf("reset audit head: %v", err)
	}
}

// SeedUser inserts a minimal users row and returns the new UUID. Tests that
// touch FK-bound tables (mfa_challenges, recovery_sessions, user_vault, ...)
// must seed a user first because the FK is ON DELETE CASCADE — without a
// row, the insert into the child table fails.
func (p *PG) SeedUser(ctx context.Context, t *testing.T, email string) string {
	t.Helper()
	var id string
	err := p.Pool.QueryRow(ctx,
		`INSERT INTO users (email) VALUES ($1) RETURNING id::text`,
		email,
	).Scan(&id)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

func runMigrations(dsn string) error {
	src, err := iofs.New(sqlpkg.MigrationsFS, sqlpkg.MigrationsPath)
	if err != nil {
		return fmt.Errorf("iofs: %w", err)
	}
	// Open via database/sql so we can hand the driver our DSN with sslmode.
	m, err := migrate.NewWithSourceInstance("iofs", src, dsn)
	if err != nil {
		return fmt.Errorf("new migrate: %w", err)
	}
	defer m.Close()
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("up: %w", err)
	}
	return nil
}

var _ = postgres.Postgres{} // keep import to make sure the driver registers

package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sxwebdev/oblivio/internal/store/repos"
	"github.com/sxwebdev/oblivio/pkg/postgres"
)

// Store aggregates the database pool and all repositories.
type Store struct {
	*repos.Repos
	pg       *postgres.DB
	testPool *pgxpool.Pool // populated by NewForTest; nil in production
}

// New creates a new Store.
func New(pg *postgres.DB) *Store {
	return &Store{
		Repos: repos.New(pg.Pool()),
		pg:    pg,
	}
}

// Pool returns the underlying pgxpool.Pool.
func (s *Store) Pool() *pgxpool.Pool {
	if s.pg == nil {
		return s.testPool
	}
	return s.pg.Pool()
}

// NewForTest builds a Store from a bare pgxpool.Pool, bypassing the
// postgres.DB lifecycle wrapper. Intended for tests that already manage
// their own pool (e.g. via testutil.NewPostgres).
func NewForTest(pool *pgxpool.Pool) *Store {
	return &Store{
		Repos:    repos.New(pool),
		testPool: pool,
	}
}

// SystemDo runs fn inside a short transaction with the RLS bypass GUC set.
// Use it from trusted backend paths (auth handlers, jobs, recovery) that
// touch RLS-protected tables outside any per-user middleware tx. The
// caller must explicitly filter rows by user_id — bypass disables RLS, it
// does NOT widen authorization.
func (s *Store) SystemDo(ctx context.Context, fn func(tx pgx.Tx) error) error {
	tx, err := s.Pool().BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("system tx: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SET LOCAL app.bypass_rls = 'true'"); err != nil {
		return fmt.Errorf("system tx: set bypass: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

package store

import (
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

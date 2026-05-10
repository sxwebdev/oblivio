package store

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sxwebdev/oblivio/internal/store/repos"
	"github.com/sxwebdev/oblivio/pkg/postgres"
)

// Store aggregates the database pool and all repositories.
type Store struct {
	*repos.Repos
	pg *postgres.DB
}

// New creates a new Store.
func New(pg *postgres.DB) *Store {
	return &Store{
		Repos: repos.New(pg.Pool()),
		pg:    pg,
	}
}

// Pool returns the underlying pgxpool.Pool.
func (s *Store) Pool() *pgxpool.Pool { return s.pg.Pool() }

package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/tkcrm/mx/launcher/ops"
	"github.com/tkcrm/mx/logger"
)

// DB wraps pgxpool.Pool with service lifecycle.
type DB struct {
	pool   *pgxpool.Pool
	logger logger.Logger
	dsn    string
}

// New creates a new postgres DB instance. The pool is opened on Start.
func New(l logger.Logger, dsn string) *DB {
	return &DB{logger: l, dsn: dsn}
}

// Name returns the service name.
func (db *DB) Name() string { return "postgres" }

// Start opens the connection pool and pings the database.
func (db *DB) Start(ctx context.Context) error {
	pool, err := pgxpool.New(ctx, db.dsn)
	if err != nil {
		return fmt.Errorf("failed to create postgres pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return fmt.Errorf("failed to ping postgres: %w", err)
	}

	db.pool = pool
	db.logger.Infof("postgres connected")
	return nil
}

// Stop closes the connection pool.
func (db *DB) Stop(_ context.Context) error {
	if db.pool != nil {
		db.pool.Close()
		db.logger.Infof("postgres disconnected")
	}
	return nil
}

// Pool returns the underlying pgxpool.Pool.
func (db *DB) Pool() *pgxpool.Pool { return db.pool }

// DB returns a *sql.DB backed by the pool (for libraries that need database/sql).
func (db *DB) DB() *sql.DB { return stdlib.OpenDBFromPool(db.pool) }

// Interval returns the health check polling interval.
func (p *DB) Interval() time.Duration { return time.Second }

// Healthy checks the health of the postgres pool.
func (p *DB) Healthy(ctx context.Context) error {
	if p.pool == nil {
		return fmt.Errorf("postgres pool is not initialized: %w", ops.ErrHealthCheckServiceStarting)
	}
	return p.pool.Ping(ctx)
}

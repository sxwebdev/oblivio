package jobs

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/sxwebdev/oblivio/internal/config"
	"github.com/sxwebdev/oblivio/internal/store"
	"github.com/tkcrm/mx/logger"
)

// pgxtx is the transaction type used by the pgxv5 River driver.
type pgxtx = pgx.Tx

// Service manages the River job queue lifecycle.
type Service struct {
	pool        *pgxpool.Pool
	st          *store.Store
	log         logger.ExtendedLogger
	riverClient *river.Client[pgxtx]
	// hasWorkers is true when at least one worker is registered. River refuses to
	// Start a client without both Queues and Workers configured, so when no
	// workers exist the service runs in insert-only mode and Start is a no-op
	// that blocks until context cancellation.
	hasWorkers bool
}

// NewService creates a new River job service and initialises the River client.
// pool must be non-nil (postgres must be started before calling this).
func NewService(
	log logger.ExtendedLogger,
	cfg config.JobsConfig,
	pool *pgxpool.Pool,
	st *store.Store,
) (*Service, error) {
	driver := riverpgxv5.New(pool)

	workers := river.NewWorkers()
	// Workers are registered as new background jobs are introduced.
	hasWorkers := false

	rcfg := &river.Config{Workers: workers}
	if hasWorkers {
		rcfg.Queues = map[string]river.QueueConfig{
			river.QueueDefault: {MaxWorkers: 10},
		}
	}

	riverClient, err := river.NewClient(driver, rcfg)
	if err != nil {
		return nil, fmt.Errorf("create river client: %w", err)
	}

	return &Service{
		pool:        pool,
		st:          st,
		log:         log,
		riverClient: riverClient,
		hasWorkers:  hasWorkers,
	}, nil
}

// Name returns the service name.
func (s *Service) Name() string { return "river-jobs" }

// Start runs the River client and blocks until ctx is cancelled.
// When no workers are registered the client is not started (River would reject
// it); the service simply waits for shutdown so it slots into the launcher.
func (s *Service) Start(ctx context.Context) error {
	if s.hasWorkers {
		if err := s.riverClient.Start(ctx); err != nil {
			return fmt.Errorf("start river client: %w", err)
		}
	}
	<-ctx.Done()
	return nil
}

// Stop gracefully shuts down the River client.
func (s *Service) Stop(ctx context.Context) error {
	if !s.hasWorkers {
		return nil
	}
	return s.riverClient.Stop(ctx)
}

// RiverClient returns the River client for use by API handlers (e.g. to insert manual jobs).
func (s *Service) RiverClient() *river.Client[pgxtx] {
	return s.riverClient
}

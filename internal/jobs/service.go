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

// Service manages the River job queue lifecycle. As of Sprint 4 it runs the
// audit-chain verifier on a daily cadence and is the home for future
// periodic maintenance work (rate-limit GC, session GC, email retry).
type Service struct {
	pool        *pgxpool.Pool
	st          *store.Store
	log         logger.ExtendedLogger
	riverClient *river.Client[pgxtx]
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
	river.AddWorker(workers, NewAuditChainVerifyWorker(pool, log))
	river.AddWorker(workers, NewSessionsGCWorker(st, log))

	periodicJobs := []*river.PeriodicJob{
		river.NewPeriodicJob(
			river.PeriodicInterval(auditChainVerifySchedule()),
			func() (river.JobArgs, *river.InsertOpts) {
				return AuditChainVerifyArgs{}, nil
			},
			&river.PeriodicJobOpts{RunOnStart: true},
		),
		river.NewPeriodicJob(
			river.PeriodicInterval(sessionsGCInterval(cfg)),
			func() (river.JobArgs, *river.InsertOpts) {
				return SessionsGCArgs{}, nil
			},
			&river.PeriodicJobOpts{RunOnStart: true},
		),
	}

	rcfg := &river.Config{
		Workers: workers,
		Queues: map[string]river.QueueConfig{
			river.QueueDefault: {MaxWorkers: 4},
		},
		PeriodicJobs: periodicJobs,
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
	}, nil
}

// Name returns the service name.
func (s *Service) Name() string { return "river-jobs" }

// Start runs the River client and blocks until ctx is cancelled.
func (s *Service) Start(ctx context.Context) error {
	if err := s.riverClient.Start(ctx); err != nil {
		return fmt.Errorf("start river client: %w", err)
	}
	<-ctx.Done()
	return nil
}

// Stop gracefully shuts down the River client.
func (s *Service) Stop(ctx context.Context) error {
	return s.riverClient.Stop(ctx)
}

// RiverClient returns the River client for use by API handlers (e.g. to insert manual jobs).
func (s *Service) RiverClient() *river.Client[pgxtx] {
	return s.riverClient
}

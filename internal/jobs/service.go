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

	// cronParser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	// balanceSchedule, err := cronParser.Parse(cfg.CheckProviderBalanceCron)
	// if err != nil {
	// 	return nil, fmt.Errorf("parse check_provider_balance_cron %q: %w", cfg.CheckProviderBalanceCron, err)
	// }

	// // Build workers first; the shared walletChecker gets its riverClient pointer wired below.
	// checker := &walletChecker{
	// 	store:      st,
	// 	tronClient: tronClient,
	// 	log:        log,
	// }
	// checkAllWorker := &CheckWalletsWorker{
	// 	store:   st,
	// 	checker: checker,
	// 	log:     log,
	// }
	// checkOneWorker := &CheckWalletWorker{
	// 	store:   st,
	// 	checker: checker,
	// 	log:     log,
	// }

	workers := river.NewWorkers()
	// river.AddWorker(workers, checkAllWorker)
	// river.AddWorker(workers, checkOneWorker)
	// river.AddWorker(workers, &DelegateResourceWorker{
	// 	store:           st,
	// 	providerManager: pm,
	// 	log:             log,
	// })
	// river.AddWorker(workers, &PollPendingOrdersWorker{
	// 	store:           st,
	// 	providerManager: pm,
	// 	timeout:         cfg.PollPendingOrdersTimeout,
	// 	log:             log,
	// })
	// river.AddWorker(workers, &CheckProviderBalanceWorker{
	// 	providerManager: pm,
	// 	log:             log,
	// })

	// periodicJobs := []*river.PeriodicJob{
	// 	river.NewPeriodicJob(
	// 		river.PeriodicInterval(cfg.CheckWalletsInterval),
	// 		func() (river.JobArgs, *river.InsertOpts) {
	// 			return CheckWalletsArgs{}, nil
	// 		},
	// 		&river.PeriodicJobOpts{RunOnStart: true},
	// 	),
	// 	river.NewPeriodicJob(
	// 		river.PeriodicInterval(cfg.PollPendingOrdersInterval),
	// 		func() (river.JobArgs, *river.InsertOpts) {
	// 			return PollPendingOrdersArgs{}, nil
	// 		},
	// 		&river.PeriodicJobOpts{RunOnStart: false},
	// 	),
	// 	river.NewPeriodicJob(
	// 		balanceSchedule,
	// 		func() (river.JobArgs, *river.InsertOpts) {
	// 			return CheckProviderBalanceArgs{}, nil
	// 		},
	// 		&river.PeriodicJobOpts{RunOnStart: true},
	// 	),
	// }

	riverClient, err := river.NewClient(driver, &river.Config{
		Queues: map[string]river.QueueConfig{
			river.QueueDefault: {MaxWorkers: 10},
		},
		Workers: workers,
		// PeriodicJobs: periodicJobs,
	})
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

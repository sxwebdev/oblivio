package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/riverqueue/river/rivermigrate"
	"github.com/sxwebdev/oblivio/internal/api"
	"github.com/sxwebdev/oblivio/internal/auth"
	"github.com/sxwebdev/oblivio/internal/config"
	"github.com/sxwebdev/oblivio/internal/jobs"
	"github.com/sxwebdev/oblivio/internal/metrics"
	"github.com/sxwebdev/oblivio/internal/store"
	"github.com/sxwebdev/oblivio/pkg/postgres"
	sqlpkg "github.com/sxwebdev/oblivio/sql"
	"github.com/tkcrm/mx/launcher"
	"github.com/tkcrm/mx/launcher/services/pingpong"
	"github.com/tkcrm/mx/logger"
	"github.com/urfave/cli/v3"
)

func startCMD() *cli.Command {
	return &cli.Command{
		Name:  "start",
		Usage: "start the oblivio service",
		Flags: []cli.Flag{cfgPathsFlag()},
		Action: func(ctx context.Context, cl *cli.Command) error {
			l := logger.NewExtended(defaultLoggerOpts()...)

			conf := new(config.Config)
			loadResult, err := config.Load(ctx, l, conf, envPrefix, cl.StringSlice("config"))
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			defer loadResult.Cleanup()

			metrics.Init(metrics.BuildInfo{
				Application: appName,
				Version:     version,
				Branch:      branch,
				Revision:    revision,
				PipelineID:  pipelineID,
			})

			// Re-init logger with config settings
			l = logger.NewExtended(append(defaultLoggerOpts(), logger.WithConfig(conf.Log))...)

			// Run app schema migrations (golang-migrate) and River schema migrations
			// before starting services so that a clean database boots successfully.
			if err := runMigrations(l, conf.Postgres.DSN()); err != nil {
				return fmt.Errorf("migrations failed: %w", err)
			}
			if err := runRiverMigrations(ctx, conf.Postgres.DSN()); err != nil {
				return fmt.Errorf("river migrations failed: %w", err)
			}

			// Open the Postgres pool synchronously so pool-dependent services can be
			// constructed before the launcher takes over lifecycle management.
			// pg is managed outside the launcher so it stays alive while other
			// services tear down via LIFO and is closed only after launcher.Run returns.
			pg := postgres.New(l, conf.Postgres.DSN())
			if err := pg.Start(ctx); err != nil {
				return fmt.Errorf("postgres start: %w", err)
			}
			defer func() {
				if err := pg.Stop(context.Background()); err != nil {
					l.Errorw("postgres stop failed", "error", err)
				}
			}()

			st := store.New(pg)

			secrets, err := auth.LoadSecrets("data/secrets", conf.Auth.AccessTokenSecretKey, conf.Auth.RefreshTokenSecretKey)
			if err != nil {
				return fmt.Errorf("load auth secrets: %w", err)
			}
			defer secrets.Close()

			authManager := auth.NewManager(secrets, st, conf.Auth.AccessTokenTTL, conf.Auth.RefreshTokenTTL)

			jobService, err := jobs.NewService(l, conf.Jobs, pg.Pool(), st)
			if err != nil {
				return fmt.Errorf("failed to create job service: %w", err)
			}

			apiServer := api.New(l, conf.Server, conf.Auth, authManager, st)

			lnc := launcher.New(
				launcher.WithName(appName),
				launcher.WithVersion(version),
				launcher.WithLogger(l),
				launcher.WithContext(ctx),
				launcher.WithOpsConfig(conf.Ops),
				launcher.WithRunnerServicesSequence(launcher.RunnerServicesSequenceLifo),
				launcher.WithAppStartStopLog(true),
			)

			lnc.ServicesRunner().Register(
				launcher.NewService(launcher.WithService(pingpong.New(l, pingpong.WithTimeout(15*time.Minute))), launcher.WithStartupPriority(1)),
				launcher.NewService(launcher.WithService(jobService), launcher.WithStartupPriority(2)),
				launcher.NewService(launcher.WithService(apiServer), launcher.WithStartupPriority(3)),
			)

			return lnc.Run()
		},
	}
}

// runMigrations applies all pending app schema migrations (golang-migrate).
func runMigrations(l logger.Logger, dsn string) error {
	src, err := iofs.New(sqlpkg.MigrationsFS, sqlpkg.MigrationsPath)
	if err != nil {
		return fmt.Errorf("failed to create migration source: %w", err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, dsn)
	if err != nil {
		return fmt.Errorf("failed to create migrator: %w", err)
	}

	m.Log = migrateLogger{l: logger.With(l, "service", "migrations")}

	defer m.Close()
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrate up: %w", err)
	}
	return nil
}

type migrateLogger struct{ l logger.Logger }

func (m migrateLogger) Printf(format string, v ...any) {
	m.l.Infof(strings.TrimRight(format, "\n"), v...)
}

func (m migrateLogger) Verbose() bool { return true }

// runRiverMigrations applies all pending River schema migrations.
func runRiverMigrations(ctx context.Context, dsn string) error {
	riverM, closePool, err := newRiverMigrator(ctx, dsn)
	if err != nil {
		return err
	}
	defer closePool()
	if _, err := riverM.Migrate(ctx, rivermigrate.DirectionUp, nil); err != nil {
		return fmt.Errorf("river migrate up: %w", err)
	}
	return nil
}

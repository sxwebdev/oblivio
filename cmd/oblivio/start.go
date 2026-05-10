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

			pg := postgres.New(l, conf.Postgres.DSN())

			// Assemble launcher (LIFO stop order).
			// pp and pg start sequentially; all others are registered in the AfterSequential hook.
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
				launcher.NewService(launcher.WithService(pg), launcher.WithStartupPriority(1)),
			)

			// below not working now
			// // Derive K_root from admin secret (env for MVP) and TPM stub
			// admin := []byte(os.Getenv("OBLIVIO_ADMIN_SECRET"))
			// nv := tpm.NewNV()
			// _ = nv
			// sk, err := keys.DeriveStoreKeys(admin, []byte("tpm_stub"))
			// if err != nil {
			// 	log.Fatalf("keys: %v", err)
			// }

			// // Open DB
			// db, err := storage.Open(cfg.DBPath, sk.KStoreMAC)
			// if err != nil {
			// 	log.Fatalf("db open: %v", err)
			// }
			// defer db.Close()

			// // Startup checks
			// if err := db.VerifyAllMACs(); err != nil {
			// 	log.Fatalf("anti-tamper mac: %v", err)
			// }
			// root, err := db.ComputeRoot()
			// if err != nil {
			// 	log.Fatalf("compute root: %v", err)
			// }
			// // Read seal and compare
			// if seal, err := db.ReadSeal(sk.KSeal); err == nil {
			// 	if seal.RootGlobal != root {
			// 		log.Fatalf("seal root mismatch")
			// 	}
			// }
			// // Write fresh seal
			// s := db.NewSeal(0, root)
			// if err := db.WriteSeal(sk.KSeal, s); err != nil {
			// 	log.Fatalf("write seal: %v", err)
			// }
			// _ = icrypto.ErrMACMismatch

			// // HTTP Server
			// srv := server.New(cfg, db)
			// if err := srv.Listen(cfg.ListenAddr); err != nil {
			// 	log.Fatal(err)
			// }

			// After pp and pg start (pool is valid), construct all pool-dependent services.
			st := store.New(pg)
			// tokenStore := tokenmanager.NewMemoryTokenStore()
			// authManager := auth.NewManager(
			// 	conf.Auth.AccessTokenSecretKey,
			// 	conf.Auth.RefreshTokenSecretKey,
			// 	20*time.Minute,
			// 	30*24*time.Hour,
			// 	tokenStore,
			// )
			// apiServer := api.New(l, conf, authManager, st, jobService.RiverClient(), pm, tronClient)

			jobService, err := jobs.NewService(l, conf.Jobs, pg.Pool(), st)
			if err != nil {
				return fmt.Errorf("failed to create job service: %w", err)
			}

			lnc.ServicesRunner().Register(
				launcher.NewService(launcher.WithService(pingpong.New(l, pingpong.WithTimeout(15*time.Minute)))),
				launcher.NewService(launcher.WithService(jobService)),
				// launcher.NewService(launcher.WithService(apiServer)),
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

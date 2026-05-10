package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
	"github.com/sxwebdev/oblivio/internal/config"
	sqlpkg "github.com/sxwebdev/oblivio/sql"
	"github.com/tkcrm/mx/logger"
	"github.com/urfave/cli/v3"
)

func migrationsCMD() *cli.Command {
	return &cli.Command{
		Name:  "migrations",
		Usage: "database migration commands",
		Commands: []*cli.Command{
			{
				Name:  "up",
				Usage: "apply all pending migrations",
				Flags: []cli.Flag{cfgPathsFlag()},
				Action: func(ctx context.Context, cl *cli.Command) error {
					m, err := newMigrate(ctx, cl)
					if err != nil {
						return err
					}
					defer m.Close()
					if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
						return fmt.Errorf("migrate up: %w", err)
					}
					fmt.Println("migrations applied")

					conf, err := loadConf(ctx, cl)
					if err != nil {
						return err
					}
					riverM, closePool, err := newRiverMigrator(ctx, conf.Postgres.DSN())
					if err != nil {
						return err
					}
					defer closePool()
					if _, err := riverM.Migrate(ctx, rivermigrate.DirectionUp, nil); err != nil {
						return fmt.Errorf("river migrate up: %w", err)
					}
					fmt.Println("river migrations applied")
					return nil
				},
			},
			{
				Name:  "down",
				Usage: "revert the last migration",
				Flags: []cli.Flag{cfgPathsFlag()},
				Action: func(ctx context.Context, cl *cli.Command) error {
					conf, err := loadConf(ctx, cl)
					if err != nil {
						return err
					}
					riverM, closePool, err := newRiverMigrator(ctx, conf.Postgres.DSN())
					if err != nil {
						return err
					}
					defer closePool()
					if _, err := riverM.Migrate(ctx, rivermigrate.DirectionDown, &rivermigrate.MigrateOpts{MaxSteps: 1}); err != nil {
						return fmt.Errorf("river migrate down: %w", err)
					}

					m, err := newMigrate(ctx, cl)
					if err != nil {
						return err
					}
					defer m.Close()
					if err := m.Steps(-1); err != nil && !errors.Is(err, migrate.ErrNoChange) {
						return fmt.Errorf("migrate down: %w", err)
					}
					fmt.Println("migration reverted")
					return nil
				},
			},
			{
				Name:  "drop",
				Usage: "drop everything in the database (irreversible)",
				Flags: []cli.Flag{cfgPathsFlag()},
				Action: func(ctx context.Context, cl *cli.Command) error {
					m, err := newMigrate(ctx, cl)
					if err != nil {
						return err
					}
					defer m.Close()
					if err := m.Drop(); err != nil {
						return fmt.Errorf("migrate drop: %w", err)
					}
					fmt.Println("database dropped")
					return nil
				},
			},
			{
				Name:      "create",
				Usage:     "create a new migration file pair",
				ArgsUsage: "<name>",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "path", Aliases: []string{"p"}, Value: "./sql/migrations"},
				},
				Action: func(_ context.Context, cl *cli.Command) error {
					name := cl.Args().First()
					if name == "" {
						return fmt.Errorf("migration name is required")
					}
					dir := cl.String("path")
					if err := os.MkdirAll(dir, 0o755); err != nil {
						return err
					}
					ts := time.Now().Format("20060102150405")
					for _, suffix := range []string{"up", "down"} {
						fname := filepath.Join(dir, fmt.Sprintf("%s_%s.%s.sql", ts, name, suffix))
						if err := os.WriteFile(fname, []byte("-- "+suffix+" migration\n"), 0o600); err != nil {
							return err
						}
						fmt.Println("created", fname)
					}
					return nil
				},
			},
		},
	}
}

func loadConf(ctx context.Context, cl *cli.Command) (*config.Config, error) {
	l := logger.NewExtended(defaultLoggerOpts()...)
	conf := new(config.Config)
	if _, err := config.Load(ctx, l, conf, envPrefix, cl.StringSlice("config")); err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	return conf, nil
}

func newMigrate(ctx context.Context, cl *cli.Command) (*migrate.Migrate, error) {
	conf, err := loadConf(ctx, cl)
	if err != nil {
		return nil, err
	}

	src, err := iofs.New(sqlpkg.MigrationsFS, sqlpkg.MigrationsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create migration source: %w", err)
	}

	m, err := migrate.NewWithSourceInstance("iofs", src, conf.Postgres.DSN())
	if err != nil {
		return nil, fmt.Errorf("failed to create migrator: %w", err)
	}

	return m, nil
}

func newRiverMigrator(ctx context.Context, dsn string) (*rivermigrate.Migrator[pgx.Tx], func(), error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("open pool: %w", err)
	}
	driver := riverpgxv5.New(pool)
	m, err := rivermigrate.New(driver, nil)
	if err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("create river migrator: %w", err)
	}
	return m, pool.Close, nil
}

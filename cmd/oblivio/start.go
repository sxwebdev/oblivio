package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/awnumar/memguard"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/riverqueue/river/rivermigrate"
	"github.com/sxwebdev/oblivio/internal/api"
	"github.com/sxwebdev/oblivio/internal/audit"
	"github.com/sxwebdev/oblivio/internal/auth"
	"github.com/sxwebdev/oblivio/internal/config"
	"github.com/sxwebdev/oblivio/internal/email"
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

func startCMD(l logger.ExtendedLogger) *cli.Command {
	return &cli.Command{
		Name:  "start",
		Usage: "start the oblivio service",
		Flags: []cli.Flag{cfgPathsFlag()},
		Action: func(ctx context.Context, cl *cli.Command) error {
			// memguard wipes locked buffers (JWT signing keys, vault token)
			// when the process catches SIGINT/SIGTERM — without this the
			// keys leak into a coredump on abnormal exit.
			memguard.CatchInterrupt()
			defer memguard.Purge()

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

			l.Infof("service build version info: %s", getBuildVersion())

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

			// Cap concurrent Argon2id evaluations BEFORE the API starts so
			// the first incoming Authorize already runs under the limit.
			// Zero/negative config falls back to runtime.NumCPU() inside
			// SetArgon2Concurrency.
			auth.SetArgon2Concurrency(conf.Auth.Argon2Server.MaxConcurrent)

			secrets, err := auth.LoadSecrets(l.Warnf, "data/secrets", conf.Auth.AccessTokenSecretKey, conf.Auth.RefreshTokenSecretKey)
			if err != nil {
				return fmt.Errorf("load auth secrets: %w", err)
			}
			defer secrets.Close()

			tokenStore := auth.NewPGTokenStore(pg.Pool())
			authManager := auth.NewManager(secrets, st, tokenStore, conf.Auth.AccessTokenTTL, conf.Auth.RefreshTokenTTL)

			// Postgres-backed stores for short-lived multi-step flows (MFA
			// challenge, recovery handshake). Backing the state in the DB
			// removes the sticky-session requirement for multi-instance
			// deploys. Cleanup runs from the periodic GC jobs registered
			// below via jobs.NewService.
			mfaSeed, err := auth.DecodeKEKSeed(os.Getenv("OBLIVIO_MFA_KEK_SEED"))
			if err != nil {
				return fmt.Errorf("OBLIVIO_MFA_KEK_SEED: %w", err)
			}
			mfaKEK, err := auth.NewMFAKEK(mfaSeed)
			if err != nil {
				return fmt.Errorf("mfa kek: %w", err)
			}
			defer mfaKEK.Close()
			if mfaKEK.IsInstanceLocal() {
				l.Warnf("mfa kek: no shared seed (OBLIVIO_MFA_KEK_SEED unset); MFA challenges " +
					"will only be valid on the instance that issued them — enable sticky " +
					"sessions on your load balancer or set the env var")
			}
			mfaStore, err := auth.NewMFAStore(st.MFAChallenges(), mfaKEK, 5*time.Minute)
			if err != nil {
				return fmt.Errorf("mfa store: %w", err)
			}
			defer mfaStore.Close()
			recoveryStore, err := auth.NewRecoveryStore(st.RecoverySessions(), 15*time.Minute)
			if err != nil {
				return fmt.Errorf("recovery store: %w", err)
			}
			defer recoveryStore.Close()

			waRP, err := buildWebAuthn(conf.WebAuthn)
			if err != nil {
				l.Warnf("webauthn disabled: %v", err)
			}

			// External anchor for the audit-chain head (plan §17.4). A nil
			// signer disables the worker; for now we always create the
			// local Ed25519 signer — it's free and provides defence
			// against a DB-only attacker. Vault transit can be wired
			// later via a different audit.Signer implementation.
			anchorSigner, err := audit.NewLocalSigner("data/secrets")
			if err != nil {
				return fmt.Errorf("audit anchor signer: %w", err)
			}

			jobService, err := jobs.NewService(l, conf.Jobs, pg.Pool(), st, tokenStore, anchorSigner)
			if err != nil {
				return fmt.Errorf("failed to create job service: %w", err)
			}

			emailer := buildEmailSender(l, conf.Email)

			apiServer := api.New(api.Deps{
				Log:           l,
				Cfg:           conf.Server,
				Auth:          conf.Auth,
				Store:         st,
				AuthManager:   authManager,
				WebAuthn:      waRP,
				MFAStore:      mfaStore,
				RecoveryStore: recoveryStore,
				Email:         emailer,
				PublicURL:     conf.Server.PublicURL,
				// AppName is the user-facing product label used in email
				// subjects and bodies. Kept separate from the binary
				// `appName` (lowercase, used for log/metrics tagging).
				AppName: "Oblivio",
			})

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

// buildEmailSender wires the email backend chosen by EmailConfig.Provider:
//   - "" → NoopSender (verification feature disabled).
//   - "log" → LogSender (writes to logger; useful in dev/CI).
//   - "smtp" → SMTPSender via wneessen/go-mail.
func buildEmailSender(l logger.ExtendedLogger, cfg config.EmailConfig) email.Sender {
	switch cfg.Provider {
	case "smtp":
		return email.NewSMTPSender(email.SMTPConfig{
			Host:          cfg.SMTP.Host,
			Port:          int(cfg.SMTP.Port),
			Username:      cfg.SMTP.Username,
			Password:      cfg.SMTP.Password,
			From:          cfg.From,
			AllowInsecure: cfg.SMTP.AllowInsecure,
		})
	case "log":
		return email.NewLogSender(l)
	default:
		return email.NewNoopSender()
	}
}

// buildWebAuthn constructs a WebAuthn relying party from config. Returns
// (nil, err) when configuration is incomplete so the caller can surface a
// warning and continue running with passkeys disabled.
func buildWebAuthn(cfg config.WebAuthnConfig) (*wa.WebAuthn, error) {
	if cfg.RPID == "" || cfg.RPOrigin == "" {
		return nil, fmt.Errorf("webauthn: rp_id and rp_origin must be set in config")
	}
	rp, err := wa.New(&wa.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPName,
		RPOrigins:     []string{cfg.RPOrigin},
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn: %w", err)
	}
	return rp, nil
}

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

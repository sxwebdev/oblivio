package repos

import (
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sxwebdev/oblivio/internal/store/repos/repo_audit_log"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_auth_sessions"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_entries"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_idempotency_keys"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_projects"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_rate_limit_buckets"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_system_state"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_user_auth"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_user_kdf_params"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_user_login_totp"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_user_vault"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_user_webauthn_credentials"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_users"
)

// Repos aggregates all entity repositories.
type Repos struct {
	usersRepo            *repo_users.Queries
	userKDFParamsRepo    *repo_user_kdf_params.Queries
	userAuthRepo         *repo_user_auth.Queries
	userVaultRepo        *repo_user_vault.Queries
	userLoginTOTPRepo    *repo_user_login_totp.Queries
	userWebAuthnRepo     *repo_user_webauthn_credentials.Queries
	authSessionsRepo     *repo_auth_sessions.Queries
	projectsRepo         *repo_projects.Queries
	entriesRepo          *repo_entries.Queries
	auditLogRepo         *repo_audit_log.Queries
	systemStateRepo      *repo_system_state.Queries
	idempotencyKeysRepo  *repo_idempotency_keys.Queries
	rateLimitBucketsRepo *repo_rate_limit_buckets.Queries
}

// New creates a new Repos instance.
func New(pool *pgxpool.Pool) *Repos {
	return &Repos{
		usersRepo:            repo_users.New(pool),
		userKDFParamsRepo:    repo_user_kdf_params.New(pool),
		userAuthRepo:         repo_user_auth.New(pool),
		userVaultRepo:        repo_user_vault.New(pool),
		userLoginTOTPRepo:    repo_user_login_totp.New(pool),
		userWebAuthnRepo:     repo_user_webauthn_credentials.New(pool),
		authSessionsRepo:     repo_auth_sessions.New(pool),
		projectsRepo:         repo_projects.New(pool),
		entriesRepo:          repo_entries.New(pool),
		auditLogRepo:         repo_audit_log.New(pool),
		systemStateRepo:      repo_system_state.New(pool),
		idempotencyKeysRepo:  repo_idempotency_keys.New(pool),
		rateLimitBucketsRepo: repo_rate_limit_buckets.New(pool),
	}
}

// Users returns the users repository.
func (r *Repos) Users(opts ...Option) *repo_users.Queries {
	options := parseOptions(opts...)
	if options.Tx != nil {
		return r.usersRepo.WithTx(options.Tx)
	}
	return r.usersRepo
}

// UserKDFParams returns the user_kdf_params repository.
func (r *Repos) UserKDFParams(opts ...Option) *repo_user_kdf_params.Queries {
	options := parseOptions(opts...)
	if options.Tx != nil {
		return r.userKDFParamsRepo.WithTx(options.Tx)
	}
	return r.userKDFParamsRepo
}

// UserAuth returns the user_auth repository.
func (r *Repos) UserAuth(opts ...Option) *repo_user_auth.Queries {
	options := parseOptions(opts...)
	if options.Tx != nil {
		return r.userAuthRepo.WithTx(options.Tx)
	}
	return r.userAuthRepo
}

// UserVault returns the user_vault repository.
func (r *Repos) UserVault(opts ...Option) *repo_user_vault.Queries {
	options := parseOptions(opts...)
	if options.Tx != nil {
		return r.userVaultRepo.WithTx(options.Tx)
	}
	return r.userVaultRepo
}

// UserLoginTOTP returns the user_login_totp repository.
func (r *Repos) UserLoginTOTP(opts ...Option) *repo_user_login_totp.Queries {
	options := parseOptions(opts...)
	if options.Tx != nil {
		return r.userLoginTOTPRepo.WithTx(options.Tx)
	}
	return r.userLoginTOTPRepo
}

// UserWebAuthn returns the user_webauthn_credentials repository.
func (r *Repos) UserWebAuthn(opts ...Option) *repo_user_webauthn_credentials.Queries {
	options := parseOptions(opts...)
	if options.Tx != nil {
		return r.userWebAuthnRepo.WithTx(options.Tx)
	}
	return r.userWebAuthnRepo
}

// AuthSessions returns the auth_sessions repository.
func (r *Repos) AuthSessions(opts ...Option) *repo_auth_sessions.Queries {
	options := parseOptions(opts...)
	if options.Tx != nil {
		return r.authSessionsRepo.WithTx(options.Tx)
	}
	return r.authSessionsRepo
}

// Projects returns the projects repository.
func (r *Repos) Projects(opts ...Option) *repo_projects.Queries {
	options := parseOptions(opts...)
	if options.Tx != nil {
		return r.projectsRepo.WithTx(options.Tx)
	}
	return r.projectsRepo
}

// Entries returns the entries repository.
func (r *Repos) Entries(opts ...Option) *repo_entries.Queries {
	options := parseOptions(opts...)
	if options.Tx != nil {
		return r.entriesRepo.WithTx(options.Tx)
	}
	return r.entriesRepo
}

// AuditLog returns the audit_log repository.
func (r *Repos) AuditLog(opts ...Option) *repo_audit_log.Queries {
	options := parseOptions(opts...)
	if options.Tx != nil {
		return r.auditLogRepo.WithTx(options.Tx)
	}
	return r.auditLogRepo
}

// SystemState returns the system_state repository.
func (r *Repos) SystemState(opts ...Option) *repo_system_state.Queries {
	options := parseOptions(opts...)
	if options.Tx != nil {
		return r.systemStateRepo.WithTx(options.Tx)
	}
	return r.systemStateRepo
}

// IdempotencyKeys returns the idempotency_keys repository.
func (r *Repos) IdempotencyKeys(opts ...Option) *repo_idempotency_keys.Queries {
	options := parseOptions(opts...)
	if options.Tx != nil {
		return r.idempotencyKeysRepo.WithTx(options.Tx)
	}
	return r.idempotencyKeysRepo
}

// RateLimitBuckets returns the rate_limit_buckets repository.
func (r *Repos) RateLimitBuckets(opts ...Option) *repo_rate_limit_buckets.Queries {
	options := parseOptions(opts...)
	if options.Tx != nil {
		return r.rateLimitBucketsRepo.WithTx(options.Tx)
	}
	return r.rateLimitBucketsRepo
}

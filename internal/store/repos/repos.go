package repos

import (
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sxwebdev/oblivio/internal/store/repos/auth_sessions"
	"github.com/sxwebdev/oblivio/internal/store/repos/user_auth"
	"github.com/sxwebdev/oblivio/internal/store/repos/user_kdf_params"
	"github.com/sxwebdev/oblivio/internal/store/repos/user_login_totp"
	"github.com/sxwebdev/oblivio/internal/store/repos/user_vault"
	"github.com/sxwebdev/oblivio/internal/store/repos/users"
)

// Repos aggregates all entity repositories.
type Repos struct {
	pool *pgxpool.Pool
}

// New creates a new Repos instance.
func New(pool *pgxpool.Pool) *Repos {
	return &Repos{pool: pool}
}

// Pool exposes the underlying pool for transactional callers.
func (r *Repos) Pool() *pgxpool.Pool { return r.pool }

// Users returns the users repository.
func (r *Repos) Users() *users.Queries { return users.New(r.pool) }

// UserKDFParams returns the user_kdf_params repository.
func (r *Repos) UserKDFParams() *user_kdf_params.Queries { return user_kdf_params.New(r.pool) }

// UserAuth returns the user_auth repository.
func (r *Repos) UserAuth() *user_auth.Queries { return user_auth.New(r.pool) }

// UserVault returns the user_vault repository.
func (r *Repos) UserVault() *user_vault.Queries { return user_vault.New(r.pool) }

// UserLoginTOTP returns the user_login_totp repository.
func (r *Repos) UserLoginTOTP() *user_login_totp.Queries { return user_login_totp.New(r.pool) }

// AuthSessions returns the auth_sessions repository.
func (r *Repos) AuthSessions() *auth_sessions.Queries { return auth_sessions.New(r.pool) }

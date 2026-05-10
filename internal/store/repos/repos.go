package repos

import (
	"github.com/jackc/pgx/v5/pgxpool"
	ordersrepo "github.com/sxwebdev/oblivio/internal/store/repos/delegation_orders"
	settingsrepo "github.com/sxwebdev/oblivio/internal/store/repos/settings"
	walletsrepo "github.com/sxwebdev/oblivio/internal/store/repos/wallets"
)

// Repos aggregates all entity repositories.
// Add one field + accessor per entity as they are introduced.
type Repos struct {
	pool *pgxpool.Pool
}

// New creates a new Repos instance.
func New(pool *pgxpool.Pool) *Repos {
	return &Repos{pool: pool}
}

// Wallets returns the wallet repository.
func (r *Repos) Wallets() *walletsrepo.Queries {
	return walletsrepo.New(r.pool)
}

// DelegationOrders returns the delegation order repository.
func (r *Repos) DelegationOrders() *ordersrepo.Queries {
	return ordersrepo.New(r.pool)
}

// Settings returns the settings repository.
func (r *Repos) Settings() *settingsrepo.Queries {
	return settingsrepo.New(r.pool)
}

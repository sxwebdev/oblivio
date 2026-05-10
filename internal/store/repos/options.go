package repos

import "github.com/jackc/pgx/v5"

// Option configures query execution options.
type Option func(*Options)

// Options holds per-query options such as an active transaction.
type Options struct {
	Tx pgx.Tx
}

func parseOptions(opts ...Option) Options {
	var o Options
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// WithTx runs the query within the provided transaction.
func WithTx(tx pgx.Tx) Option {
	return func(o *Options) { o.Tx = tx }
}

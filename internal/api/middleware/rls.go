package middleware

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type txCtxKey struct{}

// TxFromContext returns the transaction bound to the current request by
// NewRLSInterceptor. Handlers that mutate user-scoped data MUST use this
// tx — calls outside the tx bypass the RLS GUC and may return zero rows.
func TxFromContext(ctx context.Context) (pgx.Tx, bool) {
	tx, ok := ctx.Value(txCtxKey{}).(pgx.Tx)
	return tx, ok
}

// MustTxFromContext panics when no tx is bound. Use only inside authed
// handlers wrapped by the RLS interceptor.
func MustTxFromContext(ctx context.Context) pgx.Tx {
	tx, ok := TxFromContext(ctx)
	if !ok {
		panic("middleware: no tx in context (handler not wrapped by RLS interceptor?)")
	}
	return tx
}

// NewRLSInterceptor returns a Connect interceptor that, for every
// authenticated procedure, opens a short transaction and sets the
// `app.current_user_id` Postgres GUC. RLS policies installed in
// migration 005 use this GUC as the tenant predicate.
//
// Anonymous procedures (Register, Authorize, …) pass through untouched —
// they don't need RLS because they explicitly key their queries by an
// out-of-band identifier such as the email address.
func NewRLSInterceptor(pool *pgxpool.Pool) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			uc, ok := FromContext(ctx)
			if !ok {
				return next(ctx, req)
			}

			tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			if err != nil {
				return nil, connect.NewError(connect.CodeInternal, err)
			}
			committed := false
			defer func() {
				if !committed {
					_ = tx.Rollback(ctx)
				}
			}()

			// set_config(..., is_local=true) is the parameterised
			// equivalent of `SET LOCAL` — the latter rejects $-placeholders
			// because SET is parsed before plan-time substitution.
			if _, err := tx.Exec(ctx, "SELECT set_config('app.current_user_id', $1, true)", uc.UserID.String()); err != nil {
				return nil, connect.NewError(connect.CodeInternal, err)
			}

			ctx = context.WithValue(ctx, txCtxKey{}, tx)
			resp, err := next(ctx, req)
			if err != nil {
				return nil, err
			}
			if err := tx.Commit(ctx); err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return nil, connect.NewError(connect.CodeCanceled, err)
				}
				return nil, connect.NewError(connect.CodeInternal, err)
			}
			committed = true
			return resp, nil
		}
	}
}

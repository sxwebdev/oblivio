// Shared helper for re-verifying a user's auth_key inside an authenticated
// request. Used by every "sensitive change" RPC that must guard against a
// stolen access token alone (disable TOTP, remove passkey, delete account,
// toggle passkey-unlock).

package auth

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrAuthKeyMismatch wraps a failed authKey comparison. Always surfaced
// as connect.CodeUnauthenticated so external callers see a uniform error.
var ErrAuthKeyMismatch = errors.New("auth_key mismatch")

// VerifyUserAuthKey reads the stored auth_key_hash from user_auth via the
// supplied tx (which is expected to be the RLS-scoped request tx) and
// constant-time compares against the supplied authKey.
//
// Returns a Connect error directly so handlers can `return nil, err` without
// re-wrapping:
//   - CodeInvalidArgument when authKey is empty
//   - CodeInternal       when the DB lookup fails (or the underlying argon2
//     comparison errors on a corrupt PHC string)
//   - CodeUnauthenticated on a mismatch
func VerifyUserAuthKey(ctx context.Context, tx pgx.Tx, userID uuid.UUID, authKey []byte) error {
	if len(authKey) == 0 {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("auth_key required"))
	}
	var hash string
	err := tx.QueryRow(ctx, `SELECT auth_key_hash FROM user_auth WHERE user_id = $1`, userID).Scan(&hash)
	if err != nil {
		return connect.NewError(connect.CodeInternal, fmt.Errorf("load auth_key_hash: %w", err))
	}
	ok, err := VerifyAuthKey(authKey, hash)
	if err != nil {
		return connect.NewError(connect.CodeInternal, fmt.Errorf("verify auth_key: %w", err))
	}
	if !ok {
		return connect.NewError(connect.CodeUnauthenticated, ErrAuthKeyMismatch)
	}
	return nil
}

package subscriptions

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// PublishEntriesChanged emits a per-user NOTIFY announcing an entries-table
// change. Call from inside the same transaction that performed the mutation
// — the notification is queued at commit time and never fires on rollback,
// which is exactly the semantics we want.
func PublishEntriesChanged(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	return publish(ctx, tx, userID, EncodeEntriesPayload())
}

// PublishProjectsChanged is the projects-table counterpart of
// PublishEntriesChanged. Same transaction-coupling contract.
func PublishProjectsChanged(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	return publish(ctx, tx, userID, EncodeProjectsPayload())
}

func publish(ctx context.Context, tx pgx.Tx, userID uuid.UUID, payload string) error {
	// pg_notify(text, text) is the function form; the SQL NOTIFY statement
	// requires the channel name as an identifier (cannot be parameterised),
	// so we use the function variant which accepts a parameter.
	if _, err := tx.Exec(ctx, "SELECT pg_notify($1, $2)", ChannelName(userID), payload); err != nil {
		return fmt.Errorf("pg_notify: %w", err)
	}
	return nil
}

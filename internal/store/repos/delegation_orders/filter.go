package delegation_orders

import (
	"context"

	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/google/uuid"
	"github.com/huandu/go-sqlbuilder"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/sxwebdev/oblivio/internal/models"
)

// FilterParams holds optional filter criteria for listing delegation orders.
type FilterParams struct {
	WalletID      *uuid.UUID
	Status        *models.DelegationStatus
	IsManual      *bool
	TargetAddress *string
	DateFrom      pgtype.Timestamptz
	DateTo        pgtype.Timestamptz
	Limit         int32
	Offset        int32
}

// DelegationOrderWithWallet is a delegation order joined with its source
// wallet's name. WalletName is NULL for manual orders or when the wallet has
// been deleted.
type DelegationOrderWithWallet struct {
	*models.DelegationOrder
	WalletName pgtype.Text `db:"wallet_name"`
}

// prefixedDelegationOrdersColumn returns the column name qualified with the
// delegation_orders table to avoid ambiguity in joined queries.
func prefixedDelegationOrdersColumn(c ColumnName) string {
	return TableNameDelegationOrders.String() + "." + c.String()
}

// FindWithFilters lists delegation orders matching the given optional filters,
// joined with the source wallet's name.
func (q *Queries) FindWithFilters(ctx context.Context, p FilterParams) ([]*DelegationOrderWithWallet, error) {
	cols := DelegationOrdersColumnNames()
	selectCols := make([]string, 0, len(cols)+1)
	for _, c := range cols {
		selectCols = append(selectCols, prefixedDelegationOrdersColumn(c))
	}
	selectCols = append(selectCols, "wallets.name AS wallet_name")

	sb := sqlbuilder.PostgreSQL.NewSelectBuilder()
	sb.Select(selectCols...).
		From(TableNameDelegationOrders.String()).
		JoinWithOption(sqlbuilder.LeftJoin, "wallets",
			prefixedDelegationOrdersColumn(ColumnNameDelegationOrdersWalletId)+" = wallets.id")
	applyFilters(sb, p)
	sb.OrderByDesc(prefixedDelegationOrdersColumn(ColumnNameDelegationOrdersCreatedAt))
	if p.Limit > 0 {
		sb.Limit(int(p.Limit)).Offset(int(p.Offset))
	}
	query, args := sb.Build()

	items := []*DelegationOrderWithWallet{}
	err := pgxscan.Select(ctx, q.db, &items, query, args...)
	if err != nil {
		return nil, err
	}

	return items, nil
}

// CountWithFilters returns the total count of delegation orders matching the given filters.
func (q *Queries) CountWithFilters(ctx context.Context, p FilterParams) (int64, error) {
	sb := sqlbuilder.PostgreSQL.NewSelectBuilder()
	sb.Select("count(1)").From(TableNameDelegationOrders.String())
	applyFilters(sb, p)
	query, args := sb.Build()

	row := q.db.QueryRow(ctx, query, args...)
	var count int64
	return count, row.Scan(&count)
}

func applyFilters(sb *sqlbuilder.SelectBuilder, p FilterParams) {
	if p.WalletID != nil {
		sb.Where(sb.Equal(prefixedDelegationOrdersColumn(ColumnNameDelegationOrdersWalletId), *p.WalletID))
	}
	if p.Status != nil {
		sb.Where(sb.Equal(prefixedDelegationOrdersColumn(ColumnNameDelegationOrdersStatus), *p.Status))
	}
	if p.IsManual != nil {
		sb.Where(sb.Equal(prefixedDelegationOrdersColumn(ColumnNameDelegationOrdersIsManual), *p.IsManual))
	}
	if p.TargetAddress != nil && *p.TargetAddress != "" {
		sb.Where(sb.Equal(prefixedDelegationOrdersColumn(ColumnNameDelegationOrdersTargetAddress), *p.TargetAddress))
	}
	if p.DateFrom.Valid {
		sb.Where(sb.GreaterEqualThan(prefixedDelegationOrdersColumn(ColumnNameDelegationOrdersCreatedAt), p.DateFrom))
	}
	if p.DateTo.Valid {
		sb.Where(sb.LessEqualThan(prefixedDelegationOrdersColumn(ColumnNameDelegationOrdersCreatedAt), p.DateTo))
	}
}

package models

import (
	"database/sql/driver"
	"fmt"
)

// NullEntryKind mirrors sqlc's nullable enum wrapper so query parameters
// that accept an optional kind filter can be passed without losing the
// distinction between "no filter" and "kind='login'".
type NullEntryKind struct {
	EntryKind EntryKind
	Valid     bool
}

// Scan implements sql.Scanner.
func (ns *NullEntryKind) Scan(value any) error {
	if value == nil {
		ns.EntryKind, ns.Valid = "", false
		return nil
	}
	ns.Valid = true
	switch s := value.(type) {
	case string:
		ns.EntryKind = EntryKind(s)
	case []byte:
		ns.EntryKind = EntryKind(s)
	default:
		return fmt.Errorf("models: NullEntryKind.Scan unsupported type %T", value)
	}
	return nil
}

// Value implements driver.Valuer.
func (ns NullEntryKind) Value() (driver.Value, error) {
	if !ns.Valid {
		return nil, nil
	}
	return string(ns.EntryKind), nil
}

// NullAuditAction mirrors sqlc's nullable enum wrapper for audit_action.
type NullAuditAction struct {
	AuditAction AuditAction
	Valid       bool
}

// Scan implements sql.Scanner.
func (ns *NullAuditAction) Scan(value any) error {
	if value == nil {
		ns.AuditAction, ns.Valid = "", false
		return nil
	}
	ns.Valid = true
	switch s := value.(type) {
	case string:
		ns.AuditAction = AuditAction(s)
	case []byte:
		ns.AuditAction = AuditAction(s)
	default:
		return fmt.Errorf("models: NullAuditAction.Scan unsupported type %T", value)
	}
	return nil
}

// Value implements driver.Valuer.
func (ns NullAuditAction) Value() (driver.Value, error) {
	if !ns.Valid {
		return nil, nil
	}
	return string(ns.AuditAction), nil
}

package middleware

import (
	"context"
	"maps"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	"github.com/sxwebdev/oblivio/internal/audit"
	"github.com/sxwebdev/oblivio/internal/models"
)

// AuditProcedureMap maps a fully-qualified procedure name to the audit
// action that should be recorded after the handler returns successfully.
type AuditProcedureMap = map[string]models.AuditAction

// DefaultAuditProcedures lists the Sprint-2 mutations that emit audit
// events. The auth-side actions are appended explicitly inside the auth
// service (Sprint 1), so they are not present here.
var DefaultAuditProcedures = AuditProcedureMap{
	"/oblivio.v1.ProjectsService/CreateProject":    models.AuditActionProjectCreate,
	"/oblivio.v1.ProjectsService/UpdateProject":    models.AuditActionProjectUpdate,
	"/oblivio.v1.ProjectsService/DeleteProject":    models.AuditActionProjectDelete,
	"/oblivio.v1.EntriesService/CreateEntry":       models.AuditActionEntryCreate,
	"/oblivio.v1.EntriesService/UpdateEntry":       models.AuditActionEntryUpdate,
	"/oblivio.v1.EntriesService/DeleteEntry":       models.AuditActionEntryDelete,
	"/oblivio.v1.EntriesService/GetEntriesByIds":   models.AuditActionEntryView,
	"/oblivio.v1.WebAuthnService/RegisterFinish":   models.AuditActionWebauthnRegister,
	"/oblivio.v1.WebAuthnService/RemoveCredential": models.AuditActionWebauthnRemove,
	"/oblivio.v1.LoginTOTPService/Enable":          models.AuditActionTotpEnable,
	"/oblivio.v1.LoginTOTPService/Disable":         models.AuditActionTotpDisable,
}

// auditBox is a mutable slot that handlers fill in to tell the audit
// interceptor which resource was touched. context.Context is immutable, so
// we install a pointer once and let handlers write through it.
type auditBox struct {
	target uuid.UUID
	extra  map[string]any
}

type auditBoxCtxKey struct{}

func withAuditBox(ctx context.Context) (context.Context, *auditBox) {
	box := &auditBox{}
	return context.WithValue(ctx, auditBoxCtxKey{}, box), box
}

// SetAuditTarget records the UUID of the resource the current handler
// mutated. The audit interceptor reads it after the handler returns and
// writes it into audit_log.target_id. Calling it without an active audit
// scope is a no-op so plain procedures (no interceptor) still build.
func SetAuditTarget(ctx context.Context, id uuid.UUID) {
	if box, ok := ctx.Value(auditBoxCtxKey{}).(*auditBox); ok {
		box.target = id
	}
}

// SetAuditMetadata adds opaque key/value pairs to the audit_log.metadata
// JSONB for the current procedure. Used e.g. by EntriesService.GetEntriesByIds
// to record the full id batch when the interceptor only writes a single
// target_id. Repeated calls in one handler MERGE — later keys win.
func SetAuditMetadata(ctx context.Context, kv map[string]any) {
	if box, ok := ctx.Value(auditBoxCtxKey{}).(*auditBox); ok {
		if box.extra == nil {
			box.extra = make(map[string]any, len(kv))
		}
		maps.Copy(box.extra, kv)
	}
}

// NewAuditInterceptor returns a Connect interceptor that records an
// audit_log row for every procedure listed in `procedures`. Failed
// handlers do not write to the log — only successful mutations.
func NewAuditInterceptor(writer *audit.Writer, procedures AuditProcedureMap) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			action, gated := procedures[req.Spec().Procedure]
			if !gated {
				return next(ctx, req)
			}
			ctx, box := withAuditBox(ctx)
			resp, err := next(ctx, req)
			if err != nil {
				return nil, err
			}
			uc, ok := FromContext(ctx)
			if !ok {
				return resp, nil
			}
			meta := map[string]any{
				"procedure": req.Spec().Procedure,
				"device_id": uc.DeviceID,
			}
			maps.Copy(meta, box.extra)
			ev := audit.Event{
				UserID:    uuid.NullUUID{UUID: uc.UserID, Valid: true},
				Action:    action,
				TargetID:  asNullUUID(box.target),
				UserAgent: req.Header().Get("User-Agent"),
				Metadata:  meta,
			}
			// Audit failures are logged via writer.AppendOrLog; we never
			// poison a successful user-facing response with a chain bug.
			writer.AppendOrLog(ctx, ev)
			return resp, nil
		}
	}
}

func asNullUUID(v uuid.UUID) uuid.NullUUID {
	if v == uuid.Nil {
		return uuid.NullUUID{}
	}
	return uuid.NullUUID{UUID: v, Valid: true}
}

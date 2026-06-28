// Package audit writes structured records into the audit_log table.
//
// Call from any handler that mutates state. Failures are logged but
// never block the caller — audit gaps degrade observability, not safety.
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/host-yt/caddy-proxy-manager/internal/security"
)

// ActorUser, ActorAPI, ActorSystem cover all writers.
const (
	ActorUser   = "user"
	ActorAPI    = "api"
	ActorSystem = "system"
)

// Entry is the row payload. IP and UA are derived from the request when nil.
type Entry struct {
	UserID    *int64         // nil for unauthenticated / system events
	ActorType string         // ActorUser / ActorAPI / ActorSystem
	Action    string         // "plan.create", "login.success", ...
	Entity    string         // "plan", "client", "service", "route", "auth"
	EntityID  string         // string for portability (route_id, email, etc.)
	Meta      map[string]any // additional context
}

// impersonatorCtxKey carries the admin's identity when the active
// session is impersonating a client. WithImpersonator is the only sane
// way to set it; the middleware layer does that based on the session.
type impersonatorCtxKey struct{}

// Impersonator pairs the original actor's user id with the impersonated
// (acted-upon) user id so audit rows can credit accountability to the
// admin while still recording who was being acted upon.
type Impersonator struct {
	AdminUserID        int64
	ImpersonatedUserID int64
	ImpersonatedEmail  string
}

// WithImpersonator returns ctx tagged with the impersonator info. Audit
// writes done with that ctx will attribute the actor to AdminUserID and
// stamp impersonated_user_id / impersonated_email into meta.
func WithImpersonator(ctx context.Context, i Impersonator) context.Context {
	if i.AdminUserID == 0 {
		return ctx
	}
	return context.WithValue(ctx, impersonatorCtxKey{}, i)
}

// ImpersonatorFromContext is exported so middleware can introspect.
func ImpersonatorFromContext(ctx context.Context) (Impersonator, bool) {
	v, ok := ctx.Value(impersonatorCtxKey{}).(Impersonator)
	return v, ok
}

// defaultForwarder is the process-wide SIEM sink. Set once at startup via
// SetDefaultForwarder so all 149 call-sites forward without threading it.
var defaultForwarder *Forwarder

// SetDefaultForwarder registers the process-wide SIEM forwarder. Call once
// during boot. nil disables forwarding (the zero state).
func SetDefaultForwarder(f *Forwarder) { defaultForwarder = f }

// Write inserts an audit row and optionally forwards to a SIEM webhook.
// Variadic fwd keeps every existing call-site unchanged; when omitted, the
// process-wide defaultForwarder is used. Reads IP/UA from r; impersonation
// context is stamped automatically.
func Write(ctx context.Context, db *sql.DB, logger *slog.Logger, r *http.Request, e Entry, fwd ...*Forwarder) {
	if db == nil {
		return
	}
	ip, ua := "", ""
	if r != nil {
		ip = security.ClientIP(r)
		ua = r.UserAgent()
		if len(ua) > 255 {
			ua = ua[:255]
		}
	}
	if imp, ok := ImpersonatorFromContext(ctx); ok {
		adminID := imp.AdminUserID
		e.UserID = &adminID
		if e.Meta == nil {
			e.Meta = make(map[string]any, 2)
		}
		e.Meta["impersonated_user_id"] = imp.ImpersonatedUserID
		if imp.ImpersonatedEmail != "" {
			e.Meta["impersonated_email"] = imp.ImpersonatedEmail
		}
	}
	var metaJSON sql.NullString
	if len(e.Meta) > 0 {
		if b, err := json.Marshal(e.Meta); err == nil {
			metaJSON = sql.NullString{String: string(b), Valid: true}
		}
	}
	var userID sql.NullInt64
	if e.UserID != nil {
		userID = sql.NullInt64{Int64: *e.UserID, Valid: true}
	}
	if e.ActorType == "" {
		e.ActorType = ActorUser
	}
	_, err := db.ExecContext(ctx,
		`INSERT INTO audit_log (user_id, actor_type, action, entity, entity_id, ip, user_agent, meta)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		userID, e.ActorType, e.Action, e.Entity, nullableStr(e.EntityID), nullableStr(ip), nullableStr(ua), metaJSON,
	)
	if err != nil && logger != nil {
		logger.Warn("audit write failed", "action", e.Action, "err", err)
	}
	f := defaultForwarder
	if len(fwd) > 0 && fwd[0] != nil {
		f = fwd[0]
	}
	if f != nil {
		f.Send(e, ip, ua)
	}
}

// ClearAll deletes every audit_log row and records the purge action atomically.
// Both the DELETE and the replacement audit row share a transaction; if the insert
// fails the delete is rolled back so the action is never invisible.
func ClearAll(ctx context.Context, db *sql.DB, r *http.Request, e Entry) (int64, error) {
	if db == nil {
		return 0, nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck

	res, err := tx.ExecContext(ctx, `DELETE FROM audit_log`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()

	// Stamp the row count into meta before inserting the replacement record.
	if e.Meta == nil {
		e.Meta = make(map[string]any, 1)
	}
	e.Meta["rows"] = n
	ip, ua := "", ""
	if r != nil {
		ip = security.ClientIP(r)
		ua = r.UserAgent()
		if len(ua) > 255 {
			ua = ua[:255]
		}
	}
	if e.ActorType == "" {
		e.ActorType = ActorUser
	}
	var userID sql.NullInt64
	if e.UserID != nil {
		userID = sql.NullInt64{Int64: *e.UserID, Valid: true}
	}
	var metaJSON sql.NullString
	if b, merr := json.Marshal(e.Meta); merr == nil {
		metaJSON = sql.NullString{String: string(b), Valid: true}
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO audit_log (user_id, actor_type, action, entity, entity_id, ip, user_agent, meta)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		userID, e.ActorType, e.Action, e.Entity, nullableStr(e.EntityID),
		nullableStr(ip), nullableStr(ua), metaJSON,
	)
	if err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

func nullableStr(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

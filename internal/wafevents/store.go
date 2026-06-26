// Package wafevents stores and retrieves WAF event records.
// Events are kept in waf_events; the table is pruned to maxPerRoute most
// recent rows per route on each insert.
package wafevents

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

const maxPerRoute = 10_000

// Event is one WAF event record.
type Event struct {
	ID             int64
	RouteID        sql.NullInt64
	TS             time.Time
	Severity       string
	RuleID         string
	Action         string
	RemoteIP       string
	Host           string
	URI            string
	Message        string
	CreatedAt      time.Time
	AcknowledgedAt sql.NullTime
	AcknowledgedBy sql.NullInt64
	// Suppressed is set by the query layer when an active suppression matches this event.
	Suppressed bool
}

// Suppression is one waf_rule_suppressions row.
type Suppression struct {
	ID        int64
	RuleID    string
	RouteID   sql.NullInt64
	Reason    string
	CreatedBy int64
	CreatedAt time.Time
	ExpiresAt sql.NullTime
}

// Store persists and reads WAF events.
type Store struct {
	db func() *sql.DB
}

// New returns a Store backed by db.
func New(db func() *sql.DB) *Store { return &Store{db: db} }

// Insert appends one event and trims older rows beyond maxPerRoute for that route.
// Prune is best-effort; a transient failure never discards the newly inserted event.
func (s *Store) Insert(ctx context.Context, e Event) error {
	db := s.db()
	if db == nil {
		return nil
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO waf_events (route_id,ts,severity,rule_id,action,remote_ip,host,uri,message)
		 VALUES (?,?,?,?,?,?,?,?,?)`,
		e.RouteID, e.TS, e.Severity, e.RuleID, e.Action, e.RemoteIP, e.Host, e.URI, e.Message,
	); err != nil {
		return err
	}
	if e.RouteID.Valid {
		// Keep only maxPerRoute most recent rows per route.
		_, _ = db.ExecContext(ctx,
			`DELETE FROM waf_events
			 WHERE route_id = ?
			   AND id NOT IN (
			       SELECT id FROM (
			           SELECT id FROM waf_events
			           WHERE route_id = ?
			           ORDER BY ts DESC, id DESC
			           LIMIT ?
			       ) sub
			   )`,
			e.RouteID, e.RouteID, maxPerRoute,
		)
	}
	return nil
}

// Recent returns the last n events for a route, newest first.
// Pass routeID=0 to query across all routes.
func (s *Store) Recent(ctx context.Context, routeID int64, n int) ([]Event, error) {
	db := s.db()
	if db == nil {
		return nil, nil
	}
	if n <= 0 {
		n = 100
	} else if n > maxPerRoute {
		n = maxPerRoute
	}
	var (
		q    string
		args []any
	)
	if routeID > 0 {
		q = `SELECT id,route_id,ts,severity,rule_id,action,remote_ip,host,uri,message,created_at,
		            acknowledged_at,acknowledged_by
		     FROM waf_events WHERE route_id = ? ORDER BY ts DESC, id DESC LIMIT ?`
		args = []any{routeID, n}
	} else {
		q = `SELECT id,route_id,ts,severity,rule_id,action,remote_ip,host,uri,message,created_at,
		            acknowledged_at,acknowledged_by
		     FROM waf_events ORDER BY ts DESC, id DESC LIMIT ?`
		args = []any{n}
	}
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

// Filter constrains a Filtered query. Zero values are ignored.
type Filter struct {
	RouteID  int64
	Severity string
	Action   string
	RuleID   string
	Host     string
	RemoteIP string
	From     time.Time
	To       time.Time
	Limit    int
}

// MaxExportRows is the hard cap for Filtered when Limit exceeds maxPerRoute.
const MaxExportRows = 50_000

// Filtered returns events matching f, newest first.
func (s *Store) Filtered(ctx context.Context, f Filter) ([]Event, error) {
	db := s.db()
	if db == nil {
		return nil, nil
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	} else if limit > MaxExportRows {
		limit = MaxExportRows
	}

	var conds []string
	var args []any

	if f.RouteID > 0 {
		conds = append(conds, "route_id = ?")
		args = append(args, f.RouteID)
	}
	if f.Severity != "" {
		s := f.Severity
		if len(s) > 16 {
			s = s[:16]
		}
		conds = append(conds, "severity = ?")
		args = append(args, s)
	}
	if f.Action != "" {
		a := f.Action
		if len(a) > 16 {
			a = a[:16]
		}
		conds = append(conds, "action = ?")
		args = append(args, a)
	}
	if f.RuleID != "" {
		rid := f.RuleID
		if len(rid) > 128 {
			rid = rid[:128]
		}
		// Escape SQL LIKE special chars so _ is literal, not single-char wildcard.
		rid = strings.ReplaceAll(rid, `\`, `\\`)
		rid = strings.ReplaceAll(rid, "_", `\_`)
		if !strings.Contains(rid, "%") {
			rid = "%" + rid + "%"
		}
		conds = append(conds, `rule_id LIKE ? ESCAPE '\\'`)
		args = append(args, rid)
	}
	if f.Host != "" {
		h := f.Host
		if len(h) > 255 {
			h = h[:255]
		}
		conds = append(conds, "host = ?")
		args = append(args, h)
	}
	if f.RemoteIP != "" {
		ip := f.RemoteIP
		if len(ip) > 64 {
			ip = ip[:64]
		}
		conds = append(conds, "remote_ip = ?")
		args = append(args, ip)
	}
	if !f.From.IsZero() {
		conds = append(conds, "ts >= ?")
		args = append(args, f.From)
	}
	if !f.To.IsZero() {
		conds = append(conds, "ts <= ?")
		args = append(args, f.To)
	}

	var where string
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}
	q := `SELECT id,route_id,ts,severity,rule_id,action,remote_ip,host,uri,message,created_at,
	             acknowledged_at,acknowledged_by
	      FROM waf_events` + where + ` ORDER BY ts DESC, id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

func scanEvents(rows *sql.Rows) ([]Event, error) {
	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(
			&e.ID, &e.RouteID, &e.TS,
			&e.Severity, &e.RuleID, &e.Action,
			&e.RemoteIP, &e.Host, &e.URI, &e.Message, &e.CreatedAt,
			&e.AcknowledgedAt, &e.AcknowledgedBy,
		); err == nil {
			out = append(out, e)
		}
	}
	return out, rows.Err()
}

// SuppressRule inserts a new suppression record and returns its ID.
func (s *Store) SuppressRule(ctx context.Context, sup Suppression) (int64, error) {
	if s.db == nil {
		return 0, nil
	}
	db := s.db()
	if db == nil {
		return 0, nil
	}
	res, err := db.ExecContext(ctx,
		`INSERT INTO waf_rule_suppressions (rule_id, route_id, reason, created_by, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		sup.RuleID, sup.RouteID, sup.Reason, sup.CreatedBy, sup.ExpiresAt,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListSuppressions returns active suppressions, optionally filtered by route.
// Pass routeIDs=nil to include all suppressions visible to a super_admin.
// For scoped admins pass the list of accessible route IDs; global suppressions
// (route_id IS NULL) are excluded in that case.
func (s *Store) ListSuppressions(ctx context.Context, routeIDs []int64) ([]Suppression, error) {
	if s.db == nil {
		return nil, nil
	}
	db := s.db()
	if db == nil {
		return nil, nil
	}
	var q string
	var args []any
	if routeIDs == nil {
		// All suppressions (super_admin view).
		q = `SELECT id, rule_id, route_id, reason, created_by, created_at, expires_at
		     FROM waf_rule_suppressions
		     WHERE expires_at IS NULL OR expires_at > NOW()
		     ORDER BY id DESC`
	} else if len(routeIDs) == 0 {
		return nil, nil
	} else {
		// Scoped view: only per-route suppressions for accessible routes.
		placeholders := strings.Repeat("?,", len(routeIDs))
		placeholders = placeholders[:len(placeholders)-1]
		q = `SELECT id, rule_id, route_id, reason, created_by, created_at, expires_at
		     FROM waf_rule_suppressions
		     WHERE route_id IN (` + placeholders + `)
		       AND (expires_at IS NULL OR expires_at > NOW())
		     ORDER BY id DESC`
		for _, id := range routeIDs {
			args = append(args, id)
		}
	}
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Suppression
	for rows.Next() {
		var sup Suppression
		if err := rows.Scan(&sup.ID, &sup.RuleID, &sup.RouteID, &sup.Reason,
			&sup.CreatedBy, &sup.CreatedAt, &sup.ExpiresAt); err == nil {
			out = append(out, sup)
		}
	}
	return out, rows.Err()
}

// DeleteSuppression removes a suppression by ID. ownerRouteID, if non-zero,
// additionally constrains the delete to a specific route (scoped admin safety).
func (s *Store) DeleteSuppression(ctx context.Context, id int64, ownerRouteID int64) error {
	if s.db == nil {
		return nil
	}
	db := s.db()
	if db == nil {
		return nil
	}
	var err error
	if ownerRouteID > 0 {
		_, err = db.ExecContext(ctx,
			`DELETE FROM waf_rule_suppressions WHERE id = ? AND route_id = ?`,
			id, ownerRouteID,
		)
	} else {
		_, err = db.ExecContext(ctx,
			`DELETE FROM waf_rule_suppressions WHERE id = ?`, id,
		)
	}
	return err
}

// AckEvent marks one event as acknowledged by userID.
func (s *Store) AckEvent(ctx context.Context, eventID, userID int64) error {
	if s.db == nil {
		return nil
	}
	db := s.db()
	if db == nil {
		return nil
	}
	_, err := db.ExecContext(ctx,
		`UPDATE waf_events SET acknowledged_at = NOW(), acknowledged_by = ?
		 WHERE id = ? AND acknowledged_at IS NULL`,
		userID, eventID,
	)
	return err
}

// ActiveSuppressedKeys returns (ruleID, routeID-or-0) pairs for all currently
// active suppressions, used to mark events in memory after a query.
func (s *Store) ActiveSuppressedKeys(ctx context.Context) (map[suppressKey]struct{}, error) {
	if s.db == nil {
		return nil, nil
	}
	db := s.db()
	if db == nil {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx,
		`SELECT rule_id, COALESCE(route_id,0)
		 FROM waf_rule_suppressions
		 WHERE expires_at IS NULL OR expires_at > NOW()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[suppressKey]struct{})
	for rows.Next() {
		var k suppressKey
		if err := rows.Scan(&k.RuleID, &k.RouteID); err == nil {
			out[k] = struct{}{}
		}
	}
	return out, rows.Err()
}

type suppressKey struct {
	RuleID  string
	RouteID int64
}

// MarkSuppressed annotates each event with Suppressed=true when an active
// suppression matches (global or route-specific).
func MarkSuppressed(events []Event, keys map[suppressKey]struct{}) {
	if len(keys) == 0 {
		return
	}
	for i := range events {
		rID := int64(0)
		if events[i].RouteID.Valid {
			rID = events[i].RouteID.Int64
		}
		// Global suppression (route_id=0) or route-specific.
		_, global := keys[suppressKey{RuleID: events[i].RuleID, RouteID: 0}]
		_, scoped := keys[suppressKey{RuleID: events[i].RuleID, RouteID: rID}]
		if global || scoped {
			events[i].Suppressed = true
		}
	}
}

// FilteredWithSuppressions runs Filtered and annotates events with suppression state.
func (s *Store) FilteredWithSuppressions(ctx context.Context, f Filter) ([]Event, map[suppressKey]struct{}, error) {
	events, err := s.Filtered(ctx, f)
	if err != nil {
		return nil, nil, err
	}
	keys, err := s.ActiveSuppressedKeys(ctx)
	if err != nil {
		return events, nil, err
	}
	MarkSuppressed(events, keys)
	return events, keys, nil
}

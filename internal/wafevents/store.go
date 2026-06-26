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
	ID        int64
	RouteID   sql.NullInt64
	TS        time.Time
	Severity  string
	RuleID    string
	Action    string
	RemoteIP  string
	Host      string
	URI       string
	Message   string
	CreatedAt time.Time
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
		q = `SELECT id,route_id,ts,severity,rule_id,action,remote_ip,host,uri,message,created_at
		     FROM waf_events WHERE route_id = ? ORDER BY ts DESC, id DESC LIMIT ?`
		args = []any{routeID, n}
	} else {
		q = `SELECT id,route_id,ts,severity,rule_id,action,remote_ip,host,uri,message,created_at
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
	q := `SELECT id,route_id,ts,severity,rule_id,action,remote_ip,host,uri,message,created_at
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
		); err == nil {
			out = append(out, e)
		}
	}
	return out, rows.Err()
}

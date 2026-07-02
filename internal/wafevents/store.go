// Package wafevents stores and retrieves WAF event records.
// Events are kept in waf_events; the table is pruned to maxPerRoute most
// recent rows per route on each insert.
package wafevents

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/store"
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

// InsertIfNew stores an event only when its dedup key has not been seen before.
// The key is recorded in waf_seen_events (which "Clear events" never deletes),
// so a node-agent that re-ships its whole audit log - the cause of WAF events
// reappearing after a manual clear - can never resurrect cleared or pruned rows.
// Insert + ledger write share one transaction: a failed event insert rolls the
// ledger row back so the event is retried, not silently swallowed. Returns true
// when the event was newly stored.
//
// Per-route pruning is NOT done here: it is a sort over up to maxPerRoute rows
// and running it once per event made a 500-event batch exceed the ingest timeout
// (node-agent then retried the whole backlog forever). Callers prune once per
// distinct route after the batch via PruneRoute.
func (s *Store) InsertIfNew(ctx context.Context, e Event, key string) (bool, error) {
	db := s.db()
	if db == nil {
		return false, nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit
	res, err := tx.ExecContext(ctx,
		store.InsertOrIgnore()+" INTO waf_seen_events (event_hash) VALUES (?)", key)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, nil // already ingested: drop the replay
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO waf_events (route_id,ts,severity,rule_id,action,remote_ip,host,uri,message)
		 VALUES (?,?,?,?,?,?,?,?,?)`,
		e.RouteID, e.TS, e.Severity, e.RuleID, e.Action, e.RemoteIP, e.Host, e.URI, e.Message,
	); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// PruneRoute trims waf_events for one route to its maxPerRoute newest rows.
// Best-effort: run once per distinct route after a batch of inserts, not per
// event. A no-op for routeID <= 0 (unattributed events are pruned globally by
// the ledger cap, not per route).
func (s *Store) PruneRoute(ctx context.Context, routeID int64) error {
	db := s.db()
	if db == nil || routeID <= 0 {
		return nil
	}
	_, err := db.ExecContext(ctx,
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
		routeID, routeID, maxPerRoute,
	)
	return err
}

// PruneSeen caps the dedup ledger to its keep newest rows so waf_seen_events
// stays bounded regardless of traffic. keep must comfortably exceed the visible
// event count (maxPerRoute per route) or a replay could re-show a still-visible
// event. The double-nested subquery is required: MySQL rejects both a self-
// referencing DELETE target and LIMIT directly inside IN. Best-effort; the
// ingest path throttles how often it runs.
func (s *Store) PruneSeen(ctx context.Context, keep int) error {
	db := s.db()
	if db == nil || keep <= 0 {
		return nil
	}
	_, err := db.ExecContext(ctx,
		`DELETE FROM waf_seen_events
		 WHERE event_hash NOT IN (
		     SELECT event_hash FROM (
		         SELECT event_hash FROM waf_seen_events
		         ORDER BY first_seen DESC, event_hash DESC
		         LIMIT ?
		     ) sub
		 )`, keep)
	return err
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
	Offset   int // pagination offset; 0 = first page
}

// MaxExportRows is the hard cap for Filtered when Limit exceeds maxPerRoute.
const MaxExportRows = 50_000

// wafFilterWhere builds the shared WHERE clause (" WHERE ..." or "") and its
// args from f, so Filtered and CountFiltered stay in sync.
func wafFilterWhere(f Filter) (string, []any) {
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
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// Filtered returns events matching f, newest first, honoring Limit and Offset.
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
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	where, args := wafFilterWhere(f)
	q := `SELECT id,route_id,ts,severity,rule_id,action,remote_ip,host,uri,message,created_at,
	             acknowledged_at,acknowledged_by
	      FROM waf_events` + where + ` ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

// CountFiltered returns the total number of events matching f (ignoring
// Limit/Offset), used to drive pagination.
func (s *Store) CountFiltered(ctx context.Context, f Filter) (int, error) {
	db := s.db()
	if db == nil {
		return 0, nil
	}
	where, args := wafFilterWhere(f)
	var n int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM waf_events`+where, args...).Scan(&n)
	return n, err
}

// DeleteAll purges WAF events. routeID > 0 constrains the delete to one route
// (scoped-admin safety); routeID <= 0 clears every event. Returns rows removed.
func (s *Store) DeleteAll(ctx context.Context, routeID int64) (int64, error) {
	db := s.db()
	if db == nil {
		return 0, nil
	}
	var (
		res sql.Result
		err error
	)
	if routeID > 0 {
		res, err = db.ExecContext(ctx, `DELETE FROM waf_events WHERE route_id = ?`, routeID)
	} else {
		res, err = db.ExecContext(ctx, `DELETE FROM waf_events`)
	}
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
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

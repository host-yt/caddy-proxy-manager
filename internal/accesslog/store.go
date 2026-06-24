// Package accesslog stores and retrieves per-host Caddy access log entries.
// Entries are kept in the host_access_log table; the table is pruned to the
// most recent maxPerHost rows per route on each insert.
package accesslog

import (
	"context"
	"database/sql"
	"time"
)

const maxPerHost = 500

// Entry is one access-log record.
type Entry struct {
	ID        int64
	RouteID   int64
	TS        time.Time
	Method    string
	URI       string
	Status    int
	LatencyMS int
	RemoteIP  string
	UserAgent string
}

// Store persists and reads access log entries.
type Store struct {
	db func() *sql.DB
}

// New returns a Store backed by db.
func New(db func() *sql.DB) *Store { return &Store{db: db} }

// Insert appends one entry and trims older rows beyond maxPerHost.
// Best-effort: errors are not fatal to the calling request.
func (s *Store) Insert(ctx context.Context, e Entry) error {
	db := s.db()
	if db == nil {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err = tx.ExecContext(ctx,
		`INSERT INTO host_access_log (route_id,ts,method,uri,status,latency_ms,remote_ip,user_agent)
		 VALUES (?,?,?,?,?,?,?,?)`,
		e.RouteID, e.TS, e.Method, e.URI, e.Status, e.LatencyMS, e.RemoteIP, e.UserAgent,
	); err != nil {
		return err
	}
	// Keep only maxPerHost most recent rows per route.
	if _, err = tx.ExecContext(ctx,
		`DELETE FROM host_access_log
		 WHERE route_id = ?
		   AND id NOT IN (
		       SELECT id FROM (
		           SELECT id FROM host_access_log
		           WHERE route_id = ?
		           ORDER BY ts DESC, id DESC
		           LIMIT ?
		       ) sub
		   )`,
		e.RouteID, e.RouteID, maxPerHost,
	); err != nil {
		return err
	}
	return tx.Commit()
}

// Recent returns the last n entries for a route, newest first.
func (s *Store) Recent(ctx context.Context, routeID int64, n int) ([]Entry, error) {
	db := s.db()
	if db == nil {
		return nil, nil
	}
	if n <= 0 || n > maxPerHost {
		n = 100
	}
	rows, err := db.QueryContext(ctx,
		`SELECT id,route_id,ts,method,uri,status,latency_ms,remote_ip,user_agent
		 FROM host_access_log
		 WHERE route_id = ?
		 ORDER BY ts DESC, id DESC
		 LIMIT ?`,
		routeID, n,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.RouteID, &e.TS,
			&e.Method, &e.URI, &e.Status, &e.LatencyMS, &e.RemoteIP, &e.UserAgent,
		); err == nil {
			out = append(out, e)
		}
	}
	return out, rows.Err()
}

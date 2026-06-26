// Package accesslog stores and retrieves per-host Caddy access log entries.
// Entries are kept in the host_access_log table; the table is pruned to the
// most recent maxPerHost rows per route on each insert.
package accesslog

import (
	"context"
	"database/sql"
	"strings"
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

// RollupBucket is one hourly aggregate row from log_rollups.
type RollupBucket struct {
	BucketStart  time.Time
	Requests     int64
	Errors4xx    int64
	Errors5xx    int64
	LatencySumMs int64
	LatencyMaxMs int64
}

// Insert appends one entry and trims older rows beyond maxPerHost.
// The insert and the prune run in separate statements so a transient prune
// failure never silently discards the new log entry.
func (s *Store) Insert(ctx context.Context, e Entry) error {
	db := s.db()
	if db == nil {
		return nil
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO host_access_log (route_id,ts,method,uri,status,latency_ms,remote_ip,user_agent)
		 VALUES (?,?,?,?,?,?,?,?)`,
		e.RouteID, e.TS, e.Method, e.URI, e.Status, e.LatencyMS, e.RemoteIP, e.UserAgent,
	); err != nil {
		return err
	}
	// Best-effort prune: keep only maxPerHost most recent rows per route.
	_, _ = db.ExecContext(ctx,
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
	)
	// Best-effort rollup upsert into the hourly bucket; survives the prune above.
	var e4xx, e5xx int
	if e.Status >= 400 && e.Status <= 499 {
		e4xx = 1
	} else if e.Status >= 500 {
		e5xx = 1
	}
	bucket := e.TS.UTC().Truncate(time.Hour)
	_, _ = db.ExecContext(ctx,
		`INSERT INTO log_rollups
		     (route_id,bucket_start,requests,errors_4xx,errors_5xx,latency_sum_ms,latency_max_ms)
		 VALUES (?,?,1,?,?,?,?)
		 ON DUPLICATE KEY UPDATE
		     requests=requests+1,
		     errors_4xx=errors_4xx+VALUES(errors_4xx),
		     errors_5xx=errors_5xx+VALUES(errors_5xx),
		     latency_sum_ms=latency_sum_ms+VALUES(latency_sum_ms),
		     latency_max_ms=GREATEST(latency_max_ms,VALUES(latency_max_ms))`,
		e.RouteID, bucket, e4xx, e5xx, e.LatencyMS, e.LatencyMS,
	)
	return nil
}

// RollupSeries returns hourly buckets in [from,to] for one route, ascending.
func (s *Store) RollupSeries(ctx context.Context, routeID int64, from, to time.Time) ([]RollupBucket, error) {
	db := s.db()
	if db == nil {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx,
		`SELECT bucket_start,requests,errors_4xx,errors_5xx,latency_sum_ms,latency_max_ms
		 FROM log_rollups
		 WHERE route_id=? AND bucket_start>=? AND bucket_start<=?
		 ORDER BY bucket_start ASC`,
		routeID, from.UTC(), to.UTC(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RollupBucket
	for rows.Next() {
		var b RollupBucket
		if err := rows.Scan(&b.BucketStart, &b.Requests, &b.Errors4xx, &b.Errors5xx, &b.LatencySumMs, &b.LatencyMaxMs); err == nil {
			out = append(out, b)
		}
	}
	return out, rows.Err()
}

// RollupSummary aggregates all buckets >= since for one route.
// Avg latency = LatencySumMs/Requests (caller computes).
func (s *Store) RollupSummary(ctx context.Context, routeID int64, since time.Time) (RollupBucket, error) {
	db := s.db()
	if db == nil {
		return RollupBucket{}, nil
	}
	var b RollupBucket
	err := db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(requests),0),COALESCE(SUM(errors_4xx),0),COALESCE(SUM(errors_5xx),0),
		        COALESCE(SUM(latency_sum_ms),0),COALESCE(MAX(latency_max_ms),0)
		 FROM log_rollups
		 WHERE route_id=? AND bucket_start>=?`,
		routeID, since.UTC(),
	).Scan(&b.Requests, &b.Errors4xx, &b.Errors5xx, &b.LatencySumMs, &b.LatencyMaxMs)
	return b, err
}

// Recent returns the last n entries for a route, newest first.
func (s *Store) Recent(ctx context.Context, routeID int64, n int) ([]Entry, error) {
	db := s.db()
	if db == nil {
		return nil, nil
	}
	if n <= 0 {
		n = 100
	} else if n > maxPerHost {
		n = maxPerHost
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

// Filter constrains a Filtered query. Zero values are ignored.
type Filter struct {
	StatusMin  int
	StatusMax  int
	Method     string
	RemoteIP   string
	URIPattern string // SQL LIKE pattern; % wildcards are added if no % present
	From       time.Time
	To         time.Time
	Limit      int
}

// MaxExportRows is the hard cap for Filtered when Limit exceeds maxPerHost.
const MaxExportRows = 50_000

// Filtered returns entries for a route matching f, newest first.
func (s *Store) Filtered(ctx context.Context, routeID int64, f Filter) ([]Entry, error) {
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
	conds = append(conds, "route_id = ?")
	args = append(args, routeID)

	if f.StatusMin > 0 {
		conds = append(conds, "status >= ?")
		args = append(args, f.StatusMin)
	}
	if f.StatusMax > 0 {
		conds = append(conds, "status <= ?")
		args = append(args, f.StatusMax)
	}
	if f.Method != "" {
		m := f.Method
		if len(m) > 16 {
			m = m[:16]
		}
		conds = append(conds, "method = ?")
		args = append(args, strings.ToUpper(m))
	}
	if f.RemoteIP != "" {
		ip := f.RemoteIP
		if len(ip) > 64 {
			ip = ip[:64]
		}
		conds = append(conds, "remote_ip = ?")
		args = append(args, ip)
	}
	if f.URIPattern != "" {
		pat := f.URIPattern
		if len(pat) > 500 {
			pat = pat[:500]
		}
		// Escape SQL LIKE special chars so _ is literal, not single-char wildcard.
		pat = strings.ReplaceAll(pat, `\`, `\\`)
		pat = strings.ReplaceAll(pat, "_", `\_`)
		if !strings.Contains(pat, "%") {
			pat = "%" + pat + "%"
		}
		conds = append(conds, `uri LIKE ? ESCAPE '\\'`)
		args = append(args, pat)
	}
	if !f.From.IsZero() {
		conds = append(conds, "ts >= ?")
		args = append(args, f.From)
	}
	if !f.To.IsZero() {
		conds = append(conds, "ts <= ?")
		args = append(args, f.To)
	}

	q := `SELECT id,route_id,ts,method,uri,status,latency_ms,remote_ip,user_agent
	      FROM host_access_log
	      WHERE ` + strings.Join(conds, " AND ") + `
	      ORDER BY ts DESC, id DESC
	      LIMIT ?`
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, q, args...)
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

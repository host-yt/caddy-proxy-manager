package accesslog

import (
	"context"
	"strings"
	"time"
)

const (
	defaultAnalyticsWindow = 24 * time.Hour
	maxAnalyticsWindow     = 30 * 24 * time.Hour
	defaultAnalyticsLimit  = 10
	maxAnalyticsLimit      = 100
	defaultTrafficStep     = time.Hour
	minTrafficStep         = time.Minute
	maxTrafficBuckets      = 720
)

// AnalyticsFilter constrains access-log analytics. RouteID scopes the query to
// one route when positive; zero means all routes. Zero From/To values default
// to the most recent 24 hours, and very large windows are capped.
type AnalyticsFilter struct {
	RouteID int64
	From    time.Time
	To      time.Time
	Step    time.Duration // Used by TrafficTimeseries; ignored by top/bucket queries.
}

// StatusBucket groups response statuses into coarse HTTP classes.
type StatusBucket struct {
	Bucket    string
	MinStatus int
	MaxStatus int
	Count     int64
}

// URIHit is a counted exact request URI.
type URIHit struct {
	URI   string
	Count int64
}

// PathHit is a counted request path with the query string stripped.
type PathHit struct {
	Path  string
	Count int64
}

// RemoteIPHit is a counted remote client IP.
type RemoteIPHit struct {
	RemoteIP string
	Count    int64
}

// TrafficPoint is one zero-filled request-count bucket.
type TrafficPoint struct {
	Start time.Time
	Count int64
}

// StatusBuckets returns HTTP status-class counts for a route or globally.
func (s *Store) StatusBuckets(ctx context.Context, f AnalyticsFilter) ([]StatusBucket, error) {
	db := s.db()
	if db == nil {
		return nil, nil
	}
	conds, args := analyticsWhere(f, false)
	q := `SELECT CASE
		          WHEN status BETWEEN 100 AND 199 THEN '1xx'
		          WHEN status BETWEEN 200 AND 299 THEN '2xx'
		          WHEN status BETWEEN 300 AND 399 THEN '3xx'
		          WHEN status BETWEEN 400 AND 499 THEN '4xx'
		          WHEN status BETWEEN 500 AND 599 THEN '5xx'
		          ELSE 'other'
		      END AS bucket,
		      MIN(status), MAX(status), COUNT(*)
	      FROM host_access_log
	      WHERE ` + strings.Join(conds, " AND ") + `
	      GROUP BY bucket
	      ORDER BY CASE bucket
		          WHEN '1xx' THEN 1
		          WHEN '2xx' THEN 2
		          WHEN '3xx' THEN 3
		          WHEN '4xx' THEN 4
		          WHEN '5xx' THEN 5
		          ELSE 6
		      END`
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StatusBucket
	for rows.Next() {
		var b StatusBucket
		if err := rows.Scan(&b.Bucket, &b.MinStatus, &b.MaxStatus, &b.Count); err == nil {
			out = append(out, b)
		}
	}
	return out, rows.Err()
}

// TopURIs returns the most frequent exact request URIs for a route or globally.
func (s *Store) TopURIs(ctx context.Context, f AnalyticsFilter, limit int) ([]URIHit, error) {
	rows, err := s.topTextValues(ctx, f, "uri", "uri <> ''", limit)
	if err != nil {
		return nil, err
	}
	out := make([]URIHit, 0, len(rows))
	for _, row := range rows {
		out = append(out, URIHit{URI: row.value, Count: row.count})
	}
	return out, nil
}

// TopPaths returns the most frequent request paths, ignoring query strings.
func (s *Store) TopPaths(ctx context.Context, f AnalyticsFilter, limit int) ([]PathHit, error) {
	const pathExpr = "CASE WHEN LOCATE('?', uri) > 0 THEN LEFT(uri, LOCATE('?', uri) - 1) ELSE uri END"
	rows, err := s.topTextValues(ctx, f, pathExpr, "uri <> ''", limit)
	if err != nil {
		return nil, err
	}
	out := make([]PathHit, 0, len(rows))
	for _, row := range rows {
		out = append(out, PathHit{Path: row.value, Count: row.count})
	}
	return out, nil
}

// TopRemoteIPs returns the most frequent remote IPs for a route or globally.
func (s *Store) TopRemoteIPs(ctx context.Context, f AnalyticsFilter, limit int) ([]RemoteIPHit, error) {
	rows, err := s.topTextValues(ctx, f, "remote_ip", "remote_ip <> ''", limit)
	if err != nil {
		return nil, err
	}
	out := make([]RemoteIPHit, 0, len(rows))
	for _, row := range rows {
		out = append(out, RemoteIPHit{RemoteIP: row.value, Count: row.count})
	}
	return out, nil
}

// TrafficTimeseries returns zero-filled request counts over time for one route
// or globally. Step defaults to one hour and is clamped to at least one minute.
func (s *Store) TrafficTimeseries(ctx context.Context, f AnalyticsFilter) ([]TrafficPoint, error) {
	db := s.db()
	if db == nil {
		return nil, nil
	}
	from, to := normalizeAnalyticsRange(f.From, f.To)
	step := normalizeTrafficStep(f.Step)
	maxWindow := time.Duration(maxTrafficBuckets) * step
	if to.Sub(from) > maxWindow {
		from = to.Add(-maxWindow)
	}
	start := from.UTC().Truncate(step)
	last := to.UTC().Add(-time.Nanosecond).Truncate(step)
	if last.Before(start) {
		last = start
	}
	if buckets := int(last.Sub(start)/step) + 1; buckets > maxTrafficBuckets {
		start = last.Add(-time.Duration(maxTrafficBuckets-1) * step)
		from = start
	}

	conds, args := analyticsWhere(AnalyticsFilter{RouteID: f.RouteID, From: from, To: to}, true)
	stepSeconds := int64(step / time.Second)
	args = append([]any{stepSeconds, stepSeconds}, args...)
	q := `SELECT FLOOR(UNIX_TIMESTAMP(ts) / ?) * ? AS bucket, COUNT(*)
	      FROM host_access_log
	      WHERE ` + strings.Join(conds, " AND ") + `
	      GROUP BY bucket
	      ORDER BY bucket ASC`
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[int64]int64)
	for rows.Next() {
		var bucket int64
		var count int64
		if err := rows.Scan(&bucket, &count); err == nil {
			counts[bucket] = count
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]TrafficPoint, 0, int(last.Sub(start)/step)+1)
	for t := start; !t.After(last); t = t.Add(step) {
		out = append(out, TrafficPoint{
			Start: t,
			Count: counts[t.Unix()],
		})
	}
	return out, nil
}

type topTextValue struct {
	value string
	count int64
}

func (s *Store) topTextValues(ctx context.Context, f AnalyticsFilter, expr, extraCond string, limit int) ([]topTextValue, error) {
	db := s.db()
	if db == nil {
		return nil, nil
	}
	conds, args := analyticsWhere(f, false)
	if extraCond != "" {
		conds = append(conds, extraCond)
	}
	args = append(args, normalizeAnalyticsLimit(limit))
	q := `SELECT ` + expr + ` AS value, COUNT(*) AS count
	      FROM host_access_log
	      WHERE ` + strings.Join(conds, " AND ") + `
	      GROUP BY value
	      ORDER BY count DESC, value ASC
	      LIMIT ?`
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []topTextValue
	for rows.Next() {
		var row topTextValue
		if err := rows.Scan(&row.value, &row.count); err == nil {
			out = append(out, row)
		}
	}
	return out, rows.Err()
}

func analyticsWhere(f AnalyticsFilter, halfOpen bool) ([]string, []any) {
	from, to := normalizeAnalyticsRange(f.From, f.To)
	var conds []string
	var args []any
	if f.RouteID > 0 {
		conds = append(conds, "route_id = ?")
		args = append(args, f.RouteID)
	}
	conds = append(conds, "ts >= ?")
	args = append(args, from)
	if halfOpen {
		conds = append(conds, "ts < ?")
	} else {
		conds = append(conds, "ts <= ?")
	}
	args = append(args, to)
	return conds, args
}

func normalizeAnalyticsRange(from, to time.Time) (time.Time, time.Time) {
	if to.IsZero() {
		to = time.Now().UTC()
	}
	if from.IsZero() {
		from = to.Add(-defaultAnalyticsWindow)
	}
	if !from.Before(to) {
		from = to.Add(-defaultAnalyticsWindow)
	}
	if to.Sub(from) > maxAnalyticsWindow {
		from = to.Add(-maxAnalyticsWindow)
	}
	return from, to
}

func normalizeAnalyticsLimit(limit int) int {
	if limit <= 0 {
		return defaultAnalyticsLimit
	}
	if limit > maxAnalyticsLimit {
		return maxAnalyticsLimit
	}
	return limit
}

func normalizeTrafficStep(step time.Duration) time.Duration {
	if step <= 0 {
		return defaultTrafficStep
	}
	if step < minTrafficStep {
		return minTrafficStep
	}
	return step
}

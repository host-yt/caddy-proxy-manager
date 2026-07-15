package accesslog

import (
	"context"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
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

// UserAgentHit is a counted user-agent string.
type UserAgentHit struct {
	UserAgent string
	Count     int64
}

// MethodHit is a counted HTTP method.
type MethodHit struct {
	Method string
	Count  int64
}

// CountryHit is a counted ISO 3166-1 alpha-2 country code from GeoIP.
type CountryHit struct {
	Country string // empty string = unknown/no GeoIP data
	Count   int64
}

// ASNOrgHit is a counted ASN organization from the ASN lookup.
type ASNOrgHit struct {
	Org   string
	Count int64
}

// ProtoHit is a counted HTTP protocol version.
type ProtoHit struct {
	Proto string
	Count int64
}

// BytesSummary holds aggregate traffic stats over a filter window.
type BytesSummary struct {
	TotalBytes    int64 // bytes_resp sum
	AvgBytes      int64 // bytes_resp avg
	TotalBytesReq int64 // bytes_req sum (upload from clients)
}

// LatencyStats holds latency percentile summary over a filter window.
// ASN breakdown is deferred (needs separate GeoLite2-ASN.mmdb + geoip.LookupASN).
type LatencyStats struct {
	Avg float64
	P50 float64
	P95 float64
	Max float64
}

// ErrorRatePoint is one time bucket with total and error (status>=400) counts.
type ErrorRatePoint struct {
	Start      time.Time
	TotalCount int64
	ErrorCount int64
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

// TopUserAgents returns the most frequent non-empty user-agent strings.
func (s *Store) TopUserAgents(ctx context.Context, f AnalyticsFilter, limit int) ([]UserAgentHit, error) {
	rows, err := s.topTextValues(ctx, f, "user_agent", "user_agent <> ''", limit)
	if err != nil {
		return nil, err
	}
	out := make([]UserAgentHit, 0, len(rows))
	for _, row := range rows {
		out = append(out, UserAgentHit{UserAgent: row.value, Count: row.count})
	}
	return out, nil
}

// TopCountries returns the most frequent country codes from GeoIP data.
func (s *Store) TopCountries(ctx context.Context, f AnalyticsFilter, limit int) ([]CountryHit, error) {
	rows, err := s.topTextValues(ctx, f, "country", "", limit)
	if err != nil {
		return nil, err
	}
	out := make([]CountryHit, 0, len(rows))
	for _, row := range rows {
		out = append(out, CountryHit{Country: row.value, Count: row.count})
	}
	return out, nil
}

// TopASNOrgs returns the most frequent ASN organization names.
func (s *Store) TopASNOrgs(ctx context.Context, f AnalyticsFilter, limit int) ([]ASNOrgHit, error) {
	rows, err := s.topTextValues(ctx, f, "asn_org", "asn_org <> ''", limit)
	if err != nil {
		return nil, err
	}
	out := make([]ASNOrgHit, 0, len(rows))
	for _, row := range rows {
		out = append(out, ASNOrgHit{Org: row.value, Count: row.count})
	}
	return out, nil
}

// TopMethods returns the most frequent HTTP methods.
func (s *Store) TopMethods(ctx context.Context, f AnalyticsFilter, limit int) ([]MethodHit, error) {
	rows, err := s.topTextValues(ctx, f, "method", "method <> ''", limit)
	if err != nil {
		return nil, err
	}
	out := make([]MethodHit, 0, len(rows))
	for _, row := range rows {
		out = append(out, MethodHit{Method: row.value, Count: row.count})
	}
	return out, nil
}

// LatencyStats returns avg, p50, p95, and max of latency_ms.
// p95/p50 computed via OFFSET because MariaDB window functions add complexity for no gain at 500-row cap.
func (s *Store) LatencyStats(ctx context.Context, f AnalyticsFilter) (LatencyStats, error) {
	db := s.db()
	if db == nil {
		return LatencyStats{}, nil
	}

	conds, args := analyticsWhere(f, false)
	where := strings.Join(conds, " AND ")

	// Get count, avg, max in one pass.
	var total int64
	var avg, max float64
	row := db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(AVG(latency_ms), 0), COALESCE(MAX(latency_ms), 0) FROM host_access_log WHERE `+where,
		args...)
	if err := row.Scan(&total, &avg, &max); err != nil {
		return LatencyStats{}, err
	}
	if total == 0 {
		return LatencyStats{}, nil
	}

	percentile := func(frac float64) (float64, error) {
		offset := int64(float64(total) * frac)
		if offset >= total {
			offset = total - 1
		}
		pArgs := append(append([]any(nil), args...), offset)
		var v float64
		r := db.QueryRowContext(ctx,
			`SELECT COALESCE(latency_ms, 0) FROM host_access_log WHERE `+where+
				` ORDER BY latency_ms ASC LIMIT 1 OFFSET ?`,
			pArgs...)
		return v, r.Scan(&v)
	}

	p50, err := percentile(0.50)
	if err != nil {
		return LatencyStats{}, err
	}
	p95, err := percentile(0.95)
	if err != nil {
		return LatencyStats{}, err
	}

	return LatencyStats{Avg: avg, P50: p50, P95: p95, Max: max}, nil
}

// ErrorRateSeries returns per-bucket total and error (status>=400) counts using
// the same FLOOR bucketing as TrafficTimeseries.
func (s *Store) ErrorRateSeries(ctx context.Context, f AnalyticsFilter) ([]ErrorRatePoint, error) {
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
	// TIMESTAMPDIFF+DIV (not UNIX_TIMESTAMP/FLOOR): treats the DATETIME as literal
	// UTC so the bucket epoch matches Go's t.Unix() regardless of session tz, and
	// DIV yields a clean BIGINT (the decimal `/` could fail the int64 scan).
	q := `SELECT (TIMESTAMPDIFF(SECOND, '1970-01-01 00:00:00', ts) ` + store.IntDiv() + ` ?) * ? AS bucket,
		      COUNT(*) AS total,
		      SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) AS errors
		  FROM host_access_log
		  WHERE ` + strings.Join(conds, " AND ") + `
		  GROUP BY bucket
		  ORDER BY bucket ASC`
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type bucketRow struct {
		total  int64
		errors int64
	}
	counts := make(map[int64]bucketRow)
	for rows.Next() {
		var bucket, total, errors int64
		if err := rows.Scan(&bucket, &total, &errors); err == nil {
			counts[bucket] = bucketRow{total: total, errors: errors}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]ErrorRatePoint, 0, int(last.Sub(start)/step)+1)
	for t := start; !t.After(last); t = t.Add(step) {
		br := counts[t.Unix()]
		out = append(out, ErrorRatePoint{
			Start:      t,
			TotalCount: br.total,
			ErrorCount: br.errors,
		})
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
	q := `SELECT (TIMESTAMPDIFF(SECOND, '1970-01-01 00:00:00', ts) ` + store.IntDiv() + ` ?) * ? AS bucket, COUNT(*)
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

// ProtoBreakdown returns request counts grouped by HTTP protocol version.
func (s *Store) ProtoBreakdown(ctx context.Context, f AnalyticsFilter) ([]ProtoHit, error) {
	db := s.db()
	if db == nil {
		return nil, nil
	}
	conds, args := analyticsWhere(f, false)
	conds = append(conds, "proto <> ''")
	args = append(args, 10)
	q := `SELECT proto, COUNT(*) AS cnt
	      FROM host_access_log
	      WHERE ` + strings.Join(conds, " AND ") + `
	      GROUP BY proto
	      ORDER BY cnt DESC
	      LIMIT ?`
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProtoHit
	for rows.Next() {
		var h ProtoHit
		if err := rows.Scan(&h.Proto, &h.Count); err == nil {
			out = append(out, h)
		}
	}
	return out, rows.Err()
}

// TotalBandwidthBytes returns sum of bytes_resp from log_rollups over [from,to).
func (s *Store) TotalBandwidthBytes(ctx context.Context, routeID int64, from, to time.Time) (int64, error) {
	db := s.db()
	if db == nil {
		return 0, nil
	}
	var total int64
	err := db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(bytes_resp),0) FROM log_rollups WHERE route_id=? AND bucket_start>=? AND bucket_start<?`,
		routeID, from.UTC(), to.UTC(),
	).Scan(&total)
	return total, err
}

// BandwidthDayBucket aggregates response bytes for a single calendar day.
type BandwidthDayBucket struct {
	Label      string // "Mon 23"
	ShortLabel string // "Mon" - weekday abbreviation for narrow bars
	Bytes      int64
}

// BandwidthDaySeries returns daily byte totals for the days in [from,to].
func (s *Store) BandwidthDaySeries(ctx context.Context, routeID int64, from, to time.Time) ([]BandwidthDayBucket, error) {
	db := s.db()
	if db == nil {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx,
		`SELECT DATE(bucket_start) AS day, COALESCE(SUM(bytes_resp),0)
		 FROM log_rollups
		 WHERE route_id=? AND bucket_start>=? AND bucket_start<=?
		 GROUP BY day
		 ORDER BY day ASC`,
		routeID, from.UTC(), to.UTC(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BandwidthDayBucket
	for rows.Next() {
		var day string
		var bytes int64
		if err := rows.Scan(&day, &bytes); err != nil {
			continue
		}
		t, err := time.Parse("2006-01-02", day)
		if err != nil {
			continue
		}
		out = append(out, BandwidthDayBucket{
			Label:      t.Format("Mon 02"),
			ShortLabel: t.Format("Mon"),
			Bytes:      bytes,
		})
	}
	return out, rows.Err()
}

// BytesSummary returns total and average traffic bytes over the filter window.
func (s *Store) BytesSummary(ctx context.Context, f AnalyticsFilter) (BytesSummary, error) {
	db := s.db()
	if db == nil {
		return BytesSummary{}, nil
	}
	conds, args := analyticsWhere(f, false)
	q := `SELECT COALESCE(SUM(bytes_resp),0), COALESCE(AVG(bytes_resp),0), COALESCE(SUM(bytes_req),0)
	      FROM host_access_log
	      WHERE ` + strings.Join(conds, " AND ")
	var total int64
	var avg float64
	var totalReq int64
	if err := db.QueryRowContext(ctx, q, args...).Scan(&total, &avg, &totalReq); err != nil {
		return BytesSummary{}, err
	}
	return BytesSummary{TotalBytes: total, AvgBytes: int64(avg), TotalBytesReq: totalReq}, nil
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

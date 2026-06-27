package accesslog

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// openRollupTestDB opens a real DB using TEST_DB_DSN or skips.
func openRollupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set - skipping DB-backed test")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("DB not reachable: %v", err)
	}
	return db
}

// ensureRollupTable creates log_rollups if not present (avoids depending on migration order in test env).
func ensureRollupTable(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS log_rollups (
		route_id        BIGINT          NOT NULL,
		bucket_start    DATETIME        NOT NULL,
		requests        INT UNSIGNED    NOT NULL DEFAULT 0,
		errors_4xx      INT UNSIGNED    NOT NULL DEFAULT 0,
		errors_5xx      INT UNSIGNED    NOT NULL DEFAULT 0,
		latency_sum_ms  BIGINT UNSIGNED NOT NULL DEFAULT 0,
		latency_max_ms  INT UNSIGNED    NOT NULL DEFAULT 0,
		PRIMARY KEY (route_id, bucket_start)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`)
	if err != nil {
		t.Fatalf("ensure log_rollups table: %v", err)
	}
}

// TestRollupSeriesAndSummary inserts entries in distinct hourly buckets and
// verifies per-bucket counts and cross-bucket summary.
func TestRollupSeriesAndSummary(t *testing.T) {
	db := openRollupTestDB(t)
	defer db.Close()
	ensureRollupTable(t, db)

	ctx := context.Background()
	store := New(func() *sql.DB { return db }, 0)

	// Unique route ID so parallel test runs don't collide.
	routeID := time.Now().UnixNano()

	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, "DELETE FROM log_rollups WHERE route_id=?", routeID)
		_, _ = db.ExecContext(ctx, "DELETE FROM host_access_log WHERE route_id=?", routeID)
	})

	base := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)

	// Bucket 0 (10:xx): 2xx x2 (latency 10, 20)
	// Bucket 1 (11:xx): 4xx x1 (latency 30), 5xx x1 (latency 40)
	// Bucket 2 (12:xx): 2xx x1 (latency 5)
	entries := []Entry{
		{RouteID: routeID, TS: base.Add(5 * time.Minute), Status: 200, LatencyMS: 10},
		{RouteID: routeID, TS: base.Add(10 * time.Minute), Status: 200, LatencyMS: 20},
		{RouteID: routeID, TS: base.Add(1*time.Hour + 5*time.Minute), Status: 404, LatencyMS: 30},
		{RouteID: routeID, TS: base.Add(1*time.Hour + 10*time.Minute), Status: 500, LatencyMS: 40},
		{RouteID: routeID, TS: base.Add(2*time.Hour + 3*time.Minute), Status: 200, LatencyMS: 5},
	}
	for _, e := range entries {
		e.Method = "GET"
		e.URI = "/test"
		e.RemoteIP = "1.2.3.4"
		if err := store.Insert(ctx, e); err != nil {
			t.Fatalf("Insert: %v", err)
		}
	}

	from := base.Add(-time.Minute)
	to := base.Add(3 * time.Hour)

	series, err := store.RollupSeries(ctx, routeID, from, to)
	if err != nil {
		t.Fatalf("RollupSeries: %v", err)
	}
	if len(series) != 3 {
		t.Fatalf("series len = %d, want 3", len(series))
	}

	// Bucket 0: 2 requests, 0 4xx, 0 5xx, sum=30, max=20
	b0 := series[0]
	if b0.Requests != 2 {
		t.Errorf("b0.Requests = %d, want 2", b0.Requests)
	}
	if b0.Errors4xx != 0 || b0.Errors5xx != 0 {
		t.Errorf("b0 errors unexpected: 4xx=%d 5xx=%d", b0.Errors4xx, b0.Errors5xx)
	}
	if b0.LatencySumMs != 30 {
		t.Errorf("b0.LatencySumMs = %d, want 30", b0.LatencySumMs)
	}
	if b0.LatencyMaxMs != 20 {
		t.Errorf("b0.LatencyMaxMs = %d, want 20", b0.LatencyMaxMs)
	}

	// Bucket 1: 2 requests, 1 4xx, 1 5xx, sum=70, max=40
	b1 := series[1]
	if b1.Requests != 2 {
		t.Errorf("b1.Requests = %d, want 2", b1.Requests)
	}
	if b1.Errors4xx != 1 {
		t.Errorf("b1.Errors4xx = %d, want 1", b1.Errors4xx)
	}
	if b1.Errors5xx != 1 {
		t.Errorf("b1.Errors5xx = %d, want 1", b1.Errors5xx)
	}
	if b1.LatencySumMs != 70 {
		t.Errorf("b1.LatencySumMs = %d, want 70", b1.LatencySumMs)
	}
	if b1.LatencyMaxMs != 40 {
		t.Errorf("b1.LatencyMaxMs = %d, want 40", b1.LatencyMaxMs)
	}

	// Bucket 2: 1 request, sum=5, max=5
	b2 := series[2]
	if b2.Requests != 1 {
		t.Errorf("b2.Requests = %d, want 1", b2.Requests)
	}
	if b2.LatencySumMs != 5 {
		t.Errorf("b2.LatencySumMs = %d, want 5", b2.LatencySumMs)
	}

	// Summary over whole range: 5 total, 1 4xx, 1 5xx, sum=105, max=40
	summary, err := store.RollupSummary(ctx, routeID, from)
	if err != nil {
		t.Fatalf("RollupSummary: %v", err)
	}
	if summary.Requests != 5 {
		t.Errorf("summary.Requests = %d, want 5", summary.Requests)
	}
	if summary.Errors4xx != 1 {
		t.Errorf("summary.Errors4xx = %d, want 1", summary.Errors4xx)
	}
	if summary.Errors5xx != 1 {
		t.Errorf("summary.Errors5xx = %d, want 1", summary.Errors5xx)
	}
	if summary.LatencySumMs != 105 {
		t.Errorf("summary.LatencySumMs = %d, want 105", summary.LatencySumMs)
	}
	if summary.LatencyMaxMs != 40 {
		t.Errorf("summary.LatencyMaxMs = %d, want 40", summary.LatencyMaxMs)
	}
}

// TestRollupPruneSafety inserts more than maxPerHost entries for one route in one
// hour so raw rows get pruned, then asserts the rollup bucket count equals the
// total inserted. This is the key correctness property: aggregates survive prune.
func TestRollupPruneSafety(t *testing.T) {
	db := openRollupTestDB(t)
	defer db.Close()
	ensureRollupTable(t, db)

	ctx := context.Background()
	store := New(func() *sql.DB { return db }, 0)

	routeID := time.Now().UnixNano() + 1 // distinct from other test

	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, "DELETE FROM log_rollups WHERE route_id=?", routeID)
		_, _ = db.ExecContext(ctx, "DELETE FROM host_access_log WHERE route_id=?", routeID)
	})

	// Insert defaultMaxPerRoute+50 entries all in the same hour.
	total := defaultMaxPerRoute + 50
	bucket := time.Date(2026, 2, 1, 8, 0, 0, 0, time.UTC)
	for i := 0; i < total; i++ {
		e := Entry{
			RouteID:   routeID,
			TS:        bucket.Add(time.Duration(i) * time.Second),
			Method:    "GET",
			URI:       fmt.Sprintf("/p%d", i),
			Status:    200,
			LatencyMS: 1,
			RemoteIP:  "1.2.3.4",
		}
		if err := store.Insert(ctx, e); err != nil {
			t.Fatalf("Insert #%d: %v", i, err)
		}
	}

	// Confirm raw rows were pruned to maxPerHost.
	var rawCount int
	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM host_access_log WHERE route_id=?", routeID,
	).Scan(&rawCount); err != nil {
		t.Fatalf("count raw rows: %v", err)
	}
	if rawCount > defaultMaxPerRoute {
		t.Errorf("raw rows = %d, expected <= %d (prune not working)", rawCount, defaultMaxPerRoute)
	}

	// Rollup bucket must still hold the full total.
	series, err := store.RollupSeries(ctx, routeID, bucket.Add(-time.Minute), bucket.Add(time.Hour))
	if err != nil {
		t.Fatalf("RollupSeries: %v", err)
	}
	if len(series) != 1 {
		t.Fatalf("series len = %d, want 1", len(series))
	}
	if series[0].Requests != int64(total) {
		t.Errorf("rollup requests = %d, want %d (prune-safety failed)", series[0].Requests, total)
	}
}

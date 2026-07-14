package routes

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"
)

// TestRecordRTTUpsertsBucketAndLastSeen proves recordRTT updates
// caddy_nodes.last_rtt_ms and folds successive samples into the same
// 5-min node_rtt_samples bucket. Requires TEST_DB_DSN.
func TestRecordRTTUpsertsBucketAndLastSeen(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	ctx := context.Background()

	tag := fmt.Sprintf("testrtt_%d", time.Now().UnixNano())
	_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0")
	res, err := db.ExecContext(ctx,
		`INSERT INTO caddy_nodes (name, api_url, node_group_id, current_routes)
		 VALUES (?, 'http://10.0.0.9:2019', 9999, 0)`, tag)
	if err != nil {
		t.Fatalf("insert node: %v", err)
	}
	_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=1")
	nodeID, _ := res.LastInsertId()

	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, "DELETE FROM node_rtt_samples WHERE node_id = ?", nodeID)
		_, _ = db.ExecContext(ctx, "DELETE FROM caddy_nodes WHERE id = ?", nodeID)
	})

	svc := &Service{DB: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	at := time.Date(2026, 7, 14, 10, 6, 0, 0, time.UTC) // bucket 10:05

	svc.recordRTT(ctx, nodeID, 20, at)
	svc.recordRTT(ctx, nodeID, 40, at.Add(30*time.Second))

	var lastRTT int
	if err := db.QueryRowContext(ctx,
		"SELECT last_rtt_ms FROM caddy_nodes WHERE id = ?", nodeID,
	).Scan(&lastRTT); err != nil {
		t.Fatalf("read last_rtt_ms: %v", err)
	}
	if lastRTT != 40 {
		t.Errorf("last_rtt_ms = %d, want 40 (most recent sample)", lastRTT)
	}

	var avg, minMs, maxMs, samples int
	if err := db.QueryRowContext(ctx,
		"SELECT rtt_ms_avg, rtt_ms_min, rtt_ms_max, samples FROM node_rtt_samples WHERE node_id = ? AND bucket_start = ?",
		nodeID, rttBucketStart(at),
	).Scan(&avg, &minMs, &maxMs, &samples); err != nil {
		t.Fatalf("read bucket row: %v", err)
	}
	if samples != 2 {
		t.Errorf("samples = %d, want 2", samples)
	}
	if avg != 30 {
		t.Errorf("avg = %d, want 30", avg)
	}
	if minMs != 20 {
		t.Errorf("min = %d, want 20", minMs)
	}
	if maxMs != 40 {
		t.Errorf("max = %d, want 40", maxMs)
	}

	// A sample in the next 5-min window must land in a separate row.
	svc.recordRTT(ctx, nodeID, 100, at.Add(6*time.Minute))
	var bucketCount int
	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM node_rtt_samples WHERE node_id = ?", nodeID,
	).Scan(&bucketCount); err != nil {
		t.Fatalf("count buckets: %v", err)
	}
	if bucketCount != 2 {
		t.Errorf("bucket rows = %d, want 2", bucketCount)
	}
}

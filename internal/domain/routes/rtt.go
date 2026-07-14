package routes

import (
	"context"
	"database/sql"
	"math"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// rttBucketWindow is the width of one node_rtt_samples aggregation bucket.
const rttBucketWindow = 5 * time.Minute

// rttRetention bounds how long node_rtt_samples rows are kept.
const rttRetention = 7 * 24 * time.Hour

// rttPruneLimit caps rows deleted per sweep so a big backlog can't hold a
// long table lock; the next sweep picks up where this one left off.
const rttPruneLimit = 5000

// rttBucketStart truncates t to the 5-minute window it falls into (UTC).
// Pure so the bucketing rule can be unit-tested without a DB.
func rttBucketStart(t time.Time) time.Time {
	return t.UTC().Truncate(rttBucketWindow)
}

// rttStats is one bucket's running aggregate.
type rttStats struct {
	Avg     int
	Min     int
	Max     int
	Samples int
}

// foldRTTSample folds one new RTT reading into the bucket's running stats.
// Uses the incremental-mean update (avg += (new-avg)/count) instead of
// tracking a running sum, so a single INT column holds the average without
// risking overflow over a long-lived bucket. Rounds (not truncates) the
// integer step - plain integer division always floors, which biases the
// average down over many folds. Pure so it's unit-testable without a DB;
// the caller persists the result via an atomic upsert.
func foldRTTSample(prev rttStats, sampleMs int) rttStats {
	if prev.Samples <= 0 {
		return rttStats{Avg: sampleMs, Min: sampleMs, Max: sampleMs, Samples: 1}
	}
	samples := prev.Samples + 1
	step := math.Round(float64(sampleMs-prev.Avg) / float64(samples))
	avg := prev.Avg + int(step)
	return rttStats{
		Avg:     avg,
		Min:     min(prev.Min, sampleMs),
		Max:     max(prev.Max, sampleMs),
		Samples: samples,
	}
}

// recordRTT persists one health-probe RTT reading: the node's last-seen
// value plus the 5-minute bucket it belongs to. Best-effort - errors are
// logged, not returned, since this must never block the health sweep.
func (s *Service) recordRTT(ctx context.Context, nodeID int64, rttMs int, at time.Time) {
	if s.DB == nil {
		return
	}
	if _, err := s.DB.ExecContext(ctx,
		"UPDATE caddy_nodes SET last_rtt_ms = ? WHERE id = ?", rttMs, nodeID); err != nil {
		s.Logger.Warn("rtt: update last_rtt_ms", "node_id", nodeID, "err", err)
	}

	bucket := rttBucketStart(at)
	var prev rttStats
	err := s.DB.QueryRowContext(ctx,
		"SELECT rtt_ms_avg, rtt_ms_min, rtt_ms_max, samples FROM node_rtt_samples WHERE node_id=? AND bucket_start=?",
		nodeID, bucket,
	).Scan(&prev.Avg, &prev.Min, &prev.Max, &prev.Samples)
	if err != nil && err != sql.ErrNoRows {
		s.Logger.Warn("rtt: read bucket", "node_id", nodeID, "err", err)
		return
	}
	next := foldRTTSample(prev, rttMs)

	// Same node/bucket is only ever touched by one probe goroutine at a time
	// (HealthProbe is leader-gated and ticks don't overlap), so the
	// read-then-upsert above is race-free in practice.
	var upsertQ string
	if store.Driver() == "sqlite3" {
		upsertQ = `INSERT INTO node_rtt_samples (node_id, bucket_start, rtt_ms_avg, rtt_ms_min, rtt_ms_max, samples)
		           VALUES (?,?,?,?,?,?)
		           ON CONFLICT(node_id,bucket_start) DO UPDATE SET
		             rtt_ms_avg=excluded.rtt_ms_avg, rtt_ms_min=excluded.rtt_ms_min,
		             rtt_ms_max=excluded.rtt_ms_max, samples=excluded.samples`
	} else {
		upsertQ = `INSERT INTO node_rtt_samples (node_id, bucket_start, rtt_ms_avg, rtt_ms_min, rtt_ms_max, samples)
		           VALUES (?,?,?,?,?,?)
		           ON DUPLICATE KEY UPDATE
		             rtt_ms_avg=VALUES(rtt_ms_avg), rtt_ms_min=VALUES(rtt_ms_min),
		             rtt_ms_max=VALUES(rtt_ms_max), samples=VALUES(samples)`
	}
	if _, err := s.DB.ExecContext(ctx, upsertQ,
		nodeID, bucket, next.Avg, next.Min, next.Max, next.Samples); err != nil {
		s.Logger.Warn("rtt: upsert bucket", "node_id", nodeID, "err", err)
	}
}

// pruneRTTSamples deletes node_rtt_samples rows older than rttRetention.
// Capped per sweep (LIMIT) to keep each DELETE cheap; called once per
// HealthProbe sweep so a backlog drains gradually instead of one big lock.
// SQLite's stock build lacks DELETE...LIMIT, so it prunes unbounded there.
func (s *Service) pruneRTTSamples(ctx context.Context) {
	if s.DB == nil {
		return
	}
	cutoff := time.Now().UTC().Add(-rttRetention)
	var err error
	if store.Driver() == "sqlite3" {
		_, err = s.DB.ExecContext(ctx, "DELETE FROM node_rtt_samples WHERE bucket_start < ?", cutoff)
	} else {
		_, err = s.DB.ExecContext(ctx, "DELETE FROM node_rtt_samples WHERE bucket_start < ? LIMIT ?", cutoff, rttPruneLimit)
	}
	if err != nil {
		s.Logger.Warn("rtt: prune", "err", err)
	}
}

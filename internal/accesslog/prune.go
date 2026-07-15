package accesslog

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// PruneAccessLog deletes host_access_log rows older than the
// analytics.access_log_retention_days setting. This adds a time-based PII
// retention on top of the per-route row cap enforced at insert (DB-04).
// 0 or unset means no time pruning. Cutoff is computed in Go so the DELETE is
// portable across MySQL and SQLite.
func PruneAccessLog(ctx context.Context, db *sql.DB) (int64, error) {
	if db == nil {
		return 0, nil
	}
	var v string
	if err := db.QueryRowContext(ctx,
		"SELECT value FROM settings WHERE `key` = 'analytics.access_log_retention_days'").Scan(&v); err != nil {
		return 0, nil
	}
	days, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || days <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days)
	res, err := db.ExecContext(ctx, "DELETE FROM host_access_log WHERE ts < ?", cutoff)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// PruneRollups deletes log_rollups rows older than analytics.rollup_retention_days setting.
// 0 or unset means no pruning.
func PruneRollups(ctx context.Context, db *sql.DB) (int64, error) {
	if db == nil {
		return 0, nil
	}
	var v string
	if err := db.QueryRowContext(ctx,
		"SELECT value FROM settings WHERE `key` = 'analytics.rollup_retention_days'").Scan(&v); err != nil {
		return 0, nil
	}
	days, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || days <= 0 {
		return 0, nil
	}
	res, err := db.ExecContext(ctx,
		"DELETE FROM log_rollups WHERE bucket_start < ("+store.DateSubParam("DAY")+")", days)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

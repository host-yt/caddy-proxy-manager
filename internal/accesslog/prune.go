package accesslog

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
)

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
		"DELETE FROM log_rollups WHERE bucket_start < (NOW() - INTERVAL ? DAY)", days)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

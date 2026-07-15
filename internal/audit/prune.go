package audit

import (
	"context"
	"database/sql"
	"strconv"
	"strings"

	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// Prune deletes audit_log rows older than `audit.retention_days` setting
// (0 / unset = no pruning). Webhook deliveries reuse the same setting key.
// Called from a leader-only daily ticker.
func Prune(ctx context.Context, db *sql.DB) (int64, error) {
	if db == nil {
		return 0, nil
	}
	var v string
	if err := db.QueryRowContext(ctx,
		"SELECT value FROM settings WHERE `key` = 'audit.retention_days'").Scan(&v); err != nil {
		return 0, nil
	}
	days, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || days <= 0 {
		return 0, nil
	}
	res, err := db.ExecContext(ctx,
		"DELETE FROM audit_log WHERE created_at < ("+store.DateSubParam("DAY")+")", days)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	// Also prune old webhook deliveries (same retention).
	_, _ = db.ExecContext(ctx,
		"DELETE FROM webhook_deliveries WHERE created_at < ("+store.DateSubParam("DAY")+") AND status <> 'pending'", days)
	return n, nil
}

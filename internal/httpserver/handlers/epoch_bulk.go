package handlers

import (
	"context"
	"database/sql"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
)

// bumpEpochsTx invalidates every listed user's credentials in one transaction,
// so a partial failure cannot leave some sessions alive after a suspension.
func bumpEpochsTx(ctx context.Context, db *sql.DB, userIDs []int64) error {
	if db == nil || len(userIDs) == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	for _, uid := range userIDs {
		if _, err := auth.BumpEpochTx(ctx, tx, uid); err != nil && err != auth.ErrUserGone {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

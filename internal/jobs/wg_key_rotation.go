// Package jobs contains leader-only background workers.
package jobs

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/wireguard"
)

// WGKeyRotationJob rotates WireGuard peer keys that have exceeded their
// rotation cadence. Cadence is resolved peer → plan → global setting.
type WGKeyRotationJob struct {
	DB       func() *sql.DB
	Logger   *slog.Logger
	Interval time.Duration // default 6h
}

type rotationCandidate struct {
	peerID   int64
	clientID int64
}

// Run loops on Interval until ctx is cancelled.
func (j *WGKeyRotationJob) Run(ctx context.Context) {
	interval := j.Interval
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			j.tick(ctx)
		}
	}
}

func (j *WGKeyRotationJob) tick(ctx context.Context) {
	// Bound each tick so a hung DB query cannot block the job indefinitely.
	tickCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	db := j.DB()
	if db == nil {
		return
	}

	// Resolve effective rotation days: peer.key_rotation_days → MAX(plan days per client)
	// → global setting wg.key_rotation_days. The subquery for plan days prevents duplicate
	// peer rows when a client has multiple active services/plans.
	rows, err := db.QueryContext(tickCtx, `
		SELECT p.id, p.client_id
		FROM customer_wg_peer p
		LEFT JOIN (
			SELECT sv.client_id, MAX(pl.wg_key_rotation_days) AS plan_days
			FROM services sv
			JOIN plans pl ON pl.id = sv.plan_id
			GROUP BY sv.client_id
		) sp ON sp.client_id = p.client_id
		LEFT JOIN settings s ON s.key = 'wg.key_rotation_days'
		WHERE p.status = 'active'
		  AND COALESCE(
			    p.key_rotation_days,
			    sp.plan_days,
			    CAST(NULLIF(s.value,'0') AS UNSIGNED)
		      ) IS NOT NULL
		  AND COALESCE(
			    p.key_rotation_days,
			    sp.plan_days,
			    CAST(NULLIF(s.value,'0') AS UNSIGNED)
		      ) > 0
		  AND (
			(p.last_rotated_at IS NULL AND p.last_key_rotation_at IS NULL)
			OR TIMESTAMPDIFF(DAY, GREATEST(COALESCE(p.last_rotated_at, '2000-01-01'), COALESCE(p.last_key_rotation_at, '2000-01-01')), NOW()) >=
			    COALESCE(
				    p.key_rotation_days,
				    sp.plan_days,
				    CAST(NULLIF(s.value,'0') AS UNSIGNED)
			    )
		  )
	`)
	if err != nil {
		j.Logger.Error("wg key rotation query failed", "err", err)
		return
	}
	defer rows.Close()

	var candidates []rotationCandidate
	for rows.Next() {
		var c rotationCandidate
		if err := rows.Scan(&c.peerID, &c.clientID); err != nil {
			j.Logger.Warn("wg key rotation scan", "err", err)
			continue
		}
		candidates = append(candidates, c)
	}
	if err := rows.Err(); err != nil {
		j.Logger.Error("wg key rotation rows", "err", err)
		return
	}

	for _, c := range candidates {
		if err := j.rotatePeer(tickCtx, db, c.peerID); err != nil {
			j.Logger.Error("wg key rotation failed", "peer_id", c.peerID, "err", err)
			continue
		}
		j.Logger.Info("wg key rotated", "peer_id", c.peerID)
		// TODO: trigger Caddy config push for the peer's node
		// TODO: notify client about key rotation (email/SMS via notify.Customer)
	}
}

func (j *WGKeyRotationJob) rotatePeer(ctx context.Context, db *sql.DB, peerID int64) error {
	kp, err := wireguard.GenerateKeypair()
	if err != nil {
		return err
	}
	// Store pubkey; privkey management requires Encryptor — callers that need
	// encrypted storage should embed an Encryptor and extend this method.
	// Both timestamp columns are updated so admin-reissue and job-rotation share one clock.
	_, err = db.ExecContext(ctx,
		`UPDATE customer_wg_peer
		    SET pubkey = ?,
		        last_rotated_at = NOW(),
		        last_key_rotation_at = NOW(),
		        rotation_alert_sent_at = NULL,
		        status = 'pending'
		  WHERE id = ?`,
		kp.PublicKey, peerID)
	return err
}

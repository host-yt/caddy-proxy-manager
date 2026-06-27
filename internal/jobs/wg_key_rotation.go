// Package jobs contains leader-only background workers.
package jobs

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/domain/wgpeer"
	"github.com/host-yt/caddy-proxy-manager/internal/notify"
)

// NodeResyncer can push a fresh Caddy config to a node after key rotation.
type NodeResyncer interface {
	Resync(ctx context.Context, nodeID int64) error
}

// WGKeyRotationJob rotates WireGuard peer keys that have exceeded their
// rotation cadence. Cadence is resolved peer → plan → global setting.
type WGKeyRotationJob struct {
	DB       func() *sql.DB
	Logger   *slog.Logger
	Interval time.Duration // default 6h
	// Peers delegates actual rotation so the job shares key-encrypt +
	// bootstrap-token issuance with the manual RotateKey path.
	Peers    *wgpeer.Service
	Routes   NodeResyncer   // optional; triggers Caddy push after rotation
	Notifier *notify.Customer // optional; emails the client after rotation
}

type rotationCandidate struct {
	peerID   int64
	clientID int64
	nodeID   int64
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
		SELECT p.id, p.client_id, p.node_id
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
		if err := rows.Scan(&c.peerID, &c.clientID, &c.nodeID); err != nil {
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
		if j.Routes != nil && c.nodeID > 0 {
			if err := j.Routes.Resync(tickCtx, c.nodeID); err != nil {
				j.Logger.Warn("wg key rotation: caddy resync failed", "node_id", c.nodeID, "err", err)
			}
		}
		if j.Notifier != nil {
			j.Notifier.Notify(tickCtx, c.clientID,
				"[Hostyt] WireGuard key rotated",
				"Your WireGuard tunnel key was automatically rotated. "+
					"Download the updated configuration from the client portal to restore connectivity.")
		}
	}
}

func (j *WGKeyRotationJob) rotatePeer(ctx context.Context, db *sql.DB, peerID int64) error {
	// Delegate to the service so privkey encryption + bootstrap token issuance
	// follow the exact same path as a manual key rotation.
	if _, err := j.Peers.RotateKey(ctx, peerID); err != nil {
		return err
	}
	// Record in audit log; best-effort.
	_, _ = db.ExecContext(ctx,
		`INSERT INTO wg_key_rotation_log (peer_id, source) VALUES (?, 'job')`, peerID)
	return nil
}

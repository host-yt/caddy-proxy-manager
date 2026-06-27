package routes

import (
	"context"
	"database/sql"

	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
)

// ProbeNodeCapabilities queries nodes due for a capability probe (never probed or
// last probed >24h ago) and updates their feature flags in caddy_nodes.
func (s *Service) ProbeNodeCapabilities(ctx context.Context) {
	if s.DB == nil {
		return
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, api_url FROM caddy_nodes
		 WHERE is_enabled = 1 AND approved_at IS NOT NULL
		   AND (modules_probed_at IS NULL
		        OR modules_probed_at < (NOW() - INTERVAL 24 HOUR))
		 LIMIT 50`)
	if err != nil {
		s.Logger.Error("node-cap-probe: query failed", "err", err)
		return
	}
	defer rows.Close()

	type nodeRow struct {
		id     int64
		apiURL string
	}
	var nodes []nodeRow
	for rows.Next() {
		var n nodeRow
		if err := rows.Scan(&n.id, &n.apiURL); err != nil {
			s.Logger.Error("node-cap-probe: scan failed", "err", err)
			continue
		}
		nodes = append(nodes, n)
	}
	if err := rows.Err(); err != nil {
		s.Logger.Error("node-cap-probe: rows error", "err", err)
		return
	}

	for _, n := range nodes {
		probeOne(ctx, s.DB, s.Logger, n.id, n.apiURL)
	}
}

// probeOne probes a single node and writes the result back to DB.
func probeOne(ctx context.Context, db *sql.DB, logger interface {
	Info(string, ...any)
	Error(string, ...any)
}, nodeID int64, apiURL string) {
	client := caddyapi.New(apiURL)
	caps, err := caddyapi.ProbeCapabilities(ctx, client)
	if err != nil {
		logger.Error("node-cap-probe: probe failed", "node_id", nodeID, "err", err)
		return
	}
	_, err = db.ExecContext(ctx,
		`UPDATE caddy_nodes
		 SET has_waf=?, has_l4=?, has_dns_module=?, has_rate_limit=?, has_geoip=?,
		     modules_probed_at=NOW()
		 WHERE id=?`,
		boolToTiny(caps.HasWAF), boolToTiny(caps.HasL4), boolToTiny(caps.HasDNS),
		boolToTiny(caps.HasRateLimit), boolToTiny(caps.HasGeoIP), nodeID)
	if err != nil {
		logger.Error("node-cap-probe: update failed", "node_id", nodeID, "err", err)
		return
	}
	logger.Info("node-cap-probe: updated", "node_id", nodeID,
		"waf", caps.HasWAF, "l4", caps.HasL4, "dns", caps.HasDNS,
		"rate_limit", caps.HasRateLimit, "geoip", caps.HasGeoIP)
}

// boolToTiny converts bool to MySQL TINYINT(1) value.
func boolToTiny(b bool) int {
	if b {
		return 1
	}
	return 0
}

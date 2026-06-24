package alert

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
)

// nodeOffline fires for each enabled node that has been non-healthy and
// unseen for longer than the threshold. last_seen_at is the freshness
// proxy (health_status enum has no 'unreachable' state; 'down'/'degraded'
// /'unknown' all count as not-healthy).
func nodeOffline(ctx context.Context, db *sql.DB, cfg Config) []Alert {
	rows, err := db.QueryContext(ctx, `
		SELECT id, name, health_status
		  FROM caddy_nodes
		 WHERE is_enabled = 1
		   AND health_status <> 'healthy'
		   AND (last_seen_at IS NULL OR last_seen_at < (NOW() - INTERVAL ? MINUTE))`,
		cfg.NodeOfflineMinutes)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var id int64
		var name, status string
		if err := rows.Scan(&id, &name, &status); err != nil {
			continue
		}
		out = append(out, Alert{
			RuleID:   "node_offline",
			Severity: SeverityCritical,
			Title:    "Node offline: " + name,
			Detail:   fmt.Sprintf("health_status=%s for >%dm", status, cfg.NodeOfflineMinutes),
			Labels:   map[string]string{"node_id": strconv.FormatInt(id, 10), "node_name": name},
		})
	}
	return out
}

// routeFailed fires for routes stuck in status='failed' (SSL or DNS).
func routeFailed(ctx context.Context, db *sql.DB, _ Config) []Alert {
	rows, err := db.QueryContext(ctx, `
		SELECT r.id, r.domain, COALESCE(n.name, '')
		  FROM routes r
		  LEFT JOIN caddy_nodes n ON n.id = r.caddy_node_id
		 WHERE r.status = 'failed'`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var id int64
		var domain, nodeName string
		if err := rows.Scan(&id, &domain, &nodeName); err != nil {
			continue
		}
		out = append(out, Alert{
			RuleID:   "route_failed",
			Severity: SeverityWarning,
			Title:    "Route failed: " + domain,
			Detail:   "route is in 'failed' state (SSL or DNS)",
			Labels:   map[string]string{"route_id": strconv.FormatInt(id, 10), "domain": domain, "node_name": nodeName},
		})
	}
	return out
}

// certFailing fires for routes stuck in pending_ssl past the threshold =
// cert issuance not completing.
func certFailing(ctx context.Context, db *sql.DB, cfg Config) []Alert {
	rows, err := db.QueryContext(ctx, `
		SELECT id, domain
		  FROM routes
		 WHERE status = 'pending_ssl'
		   AND updated_at < (NOW() - INTERVAL ? MINUTE)`,
		cfg.CertStuckMinutes)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var id int64
		var domain string
		if err := rows.Scan(&id, &domain); err != nil {
			continue
		}
		out = append(out, Alert{
			RuleID:   "cert_failing",
			Severity: SeverityWarning,
			Title:    "Certificate stuck: " + domain,
			Detail:   fmt.Sprintf("pending_ssl for >%dm; issuance may be blocked", cfg.CertStuckMinutes),
			Labels:   map[string]string{"route_id": strconv.FormatInt(id, 10), "domain": domain},
		})
	}
	return out
}

// wgTunnelStale fires for active WG peers whose last handshake is older
// than the threshold. Column is `name` (not peer_name) per schema 00020.
func wgTunnelStale(ctx context.Context, db *sql.DB, cfg Config) []Alert {
	rows, err := db.QueryContext(ctx, `
		SELECT id, name, TIMESTAMPDIFF(SECOND, last_handshake_at, NOW()) AS age_sec
		  FROM customer_wg_peer
		 WHERE status = 'active'
		   AND last_handshake_at IS NOT NULL
		   AND last_handshake_at < (NOW() - INTERVAL ? SECOND)`,
		cfg.WGStaleSeconds)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var id, ageSec int64
		var name string
		if err := rows.Scan(&id, &name, &ageSec); err != nil {
			continue
		}
		out = append(out, Alert{
			RuleID:   "wg_tunnel_stale",
			Severity: SeverityWarning,
			Title:    "WG tunnel stale: " + name,
			Detail:   fmt.Sprintf("no handshake for %ds", ageSec),
			Labels: map[string]string{
				"peer_id": strconv.FormatInt(id, 10), "peer_name": name,
				"age_sec": strconv.FormatInt(ageSec, 10),
			},
		})
	}
	return out
}

// dbPoolSaturated uses sql.DB.Stats() introspection - no query needed.
// Fires if open/max connections is at or above the configured ratio.
func dbPoolSaturated(_ context.Context, db *sql.DB, cfg Config) []Alert {
	s := db.Stats()
	if s.MaxOpenConnections == 0 {
		return nil // unlimited pool - nothing to saturate
	}
	pct := float64(s.OpenConnections) / float64(s.MaxOpenConnections)
	if pct < cfg.DBPoolSaturationPct {
		return nil
	}
	return []Alert{{
		RuleID:   "db_pool_saturated",
		Severity: SeverityWarning,
		Title:    "DB connection pool near saturation",
		Detail:   fmt.Sprintf("%.0f%% of pool used (%d/%d)", pct*100, s.OpenConnections, s.MaxOpenConnections),
		Labels:   map[string]string{"pct": fmt.Sprintf("%.2f", pct)},
	}}
}

// KnownRuleIDs is the canonical rule list used by the admin filter UI.
func KnownRuleIDs() []string {
	return []string{"node_offline", "route_failed", "cert_failing", "wg_tunnel_stale", "db_pool_saturated"}
}

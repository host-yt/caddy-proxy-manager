package alert

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/go-sql-driver/mysql"
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

// drillStale fires when the most recent successful restore drill is older than
// the configured threshold, or has never run. Threshold in days from config.
// Skips (no alert) on first boot before the table exists (MySQL 1146).
func drillStale(ctx context.Context, db *sql.DB, cfg Config) []Alert {
	threshold := cfg.DrillStaleDays
	if threshold <= 0 {
		threshold = 7
	}
	var lastSuccess sql.NullTime
	err := db.QueryRowContext(ctx,
		`SELECT MAX(finished_at)
		   FROM restore_drill_status
		  WHERE success = 1
		    AND finished_at > (NOW() - INTERVAL ? DAY)`,
		threshold,
	).Scan(&lastSuccess)
	if err != nil {
		var me *mysql.MySQLError
		// Table not yet migrated - suppress false alert on first boot.
		if errors.As(err, &me) && me.Number == 1146 {
			return nil
		}
		// Any other DB error: suppress to avoid spurious alerts.
		return nil
	}
	if lastSuccess.Valid {
		return nil // recent success exists — no alert
	}
	return []Alert{{
		RuleID:   "drill_stale",
		Severity: SeverityWarning,
		Title:    "Restore drill stale",
		Detail:   fmt.Sprintf("no successful restore drill in the last %d days", threshold),
		Labels:   map[string]string{},
	}}
}

// wgKeyNotFetched fires for peers where a post-rotation bootstrap token
// exists unconsumed beyond the grace window - customer never downloaded
// the new config after a key rotation.
func wgKeyNotFetched(ctx context.Context, db *sql.DB, cfg Config, log *slog.Logger) []Alert {
	grace := cfg.WGRotationFetchGraceHours
	if grace <= 0 {
		grace = 48
	}
	// Fire only when: peer was rotated, the grace window has elapsed, AND a
	// bootstrap token issued AFTER that rotation is still unconsumed.
	// Keying off expires_at caused false positives (pre-rotation tokens or
	// already-consumed rows could satisfy the old join condition).
	rows, err := db.QueryContext(ctx, `
		SELECT p.id, p.name
		  FROM customer_wg_peer p
		 WHERE p.last_rotated_at IS NOT NULL
		   AND p.last_rotated_at < (NOW() - INTERVAL ? HOUR)
		   AND (p.rotation_alert_sent_at IS NULL OR p.rotation_alert_sent_at < p.last_rotated_at)
		   AND EXISTS (
		         SELECT 1 FROM customer_wg_bootstrap b
		          WHERE b.peer_id = p.id
		            AND b.created_at > p.last_rotated_at
		            AND b.consumed_at IS NULL
		       )`,
		grace)
	if err != nil {
		var me *mysql.MySQLError
		// Table not yet migrated - suppress false alert on first boot.
		if errors.As(err, &me) && me.Number == 1146 {
			return nil
		}
		// Log unexpected DB errors rather than silently discarding them.
		log.Error("wgKeyNotFetched query failed", "err", err)
		return nil
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var id int64
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			continue
		}
		// Mark sent to avoid re-firing until the next rotation.
		_, _ = db.ExecContext(ctx,
			`UPDATE customer_wg_peer SET rotation_alert_sent_at=NOW() WHERE id=?`, id)
		out = append(out, Alert{
			RuleID:   "wg_key_not_fetched",
			Severity: SeverityWarning,
			Title:    "WG key not fetched: " + name,
			Detail:   fmt.Sprintf("bootstrap token unconsumed >%dh after rotation", grace),
			Labels:   map[string]string{"peer_id": strconv.FormatInt(id, 10), "peer_name": name},
		})
	}
	return out
}

// manualCertExpiry fires for manually imported certs nearing expiry or already
// expired. Severity escalates to Critical when the cert is past its NotAfter.
// Phase label ("warn"/"expired") is included so Warning->Critical escalation
// gets a distinct dedupe key and is not suppressed by the cooldown window.
func manualCertExpiry(ctx context.Context, db *sql.DB, cfg Config, log *slog.Logger) []Alert {
	threshold := cfg.ManualCertDaysWarn
	if threshold <= 0 {
		threshold = 30
	}
	rows, err := db.QueryContext(ctx, `
		SELECT id, name, common_name, route_id, not_after,
		       TIMESTAMPDIFF(DAY, NOW(), not_after) AS days_left
		  FROM manual_certs
		 WHERE not_after < (NOW() + INTERVAL ? DAY)`,
		threshold)
	if err != nil {
		var me *mysql.MySQLError
		// Table not yet migrated - suppress false alert on first boot.
		if errors.As(err, &me) && me.Number == 1146 {
			return nil
		}
		// Any other error (schema drift, timeout, permissions) must NOT silently
		// disable expiry monitoring - that is the exact failure this rule exists
		// to prevent. Surface it as a degraded-monitoring alert so operators know
		// they are flying blind on cert expiry.
		return []Alert{degradedMonitorAlert(log, "manual cert expiry query failed", err)}
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var id int64
		var name, cn string
		var routeID sql.NullInt64
		var notAfter time.Time
		var daysLeft int
		if err := rows.Scan(&id, &name, &cn, &routeID, &notAfter, &daysLeft); err != nil {
			if log != nil {
				log.Error("manual cert expiry row scan", "err", err)
			}
			continue
		}
		label := name
		if label == "" {
			label = cn
		}
		severity, phase, detail := classifyManualCert(time.Now(), notAfter, daysLeft)
		labels := map[string]string{
			"cert_id": strconv.FormatInt(id, 10),
			"cn":      cn,
			// Phase differentiates warn vs expired so the cooldown does not
			// suppress a Critical escalation that follows a Warning fire.
			"phase": phase,
		}
		if routeID.Valid {
			labels["route_id"] = strconv.FormatInt(routeID.Int64, 10)
		}
		out = append(out, Alert{
			RuleID:   "manual_cert_expiry",
			Severity: severity,
			Title:    "Manual cert expiring: " + label,
			Detail:   detail,
			Labels:   labels,
		})
	}
	// A mid-iteration error leaves partial data; surface it instead of acting on
	// a possibly-incomplete set (a specific expiring cert could be hidden).
	if err := rows.Err(); err != nil {
		out = append(out, degradedMonitorAlert(log, "manual cert expiry iteration failed", err))
	}
	return out
}

// degradedMonitorAlert builds a stable Critical alert signalling that a
// monitoring rule itself failed. Stable dedupe labels (phase=monitor_degraded)
// keep it from spamming while the fault persists.
func degradedMonitorAlert(log *slog.Logger, msg string, err error) Alert {
	if log != nil {
		log.Error(msg, "err", err)
	}
	return Alert{
		RuleID:   "manual_cert_expiry",
		Severity: SeverityCritical,
		Title:    "Manual cert expiry monitoring degraded",
		Detail:   "expiry checks are failing - certs may expire unnoticed until this is fixed",
		Labels:   map[string]string{"phase": "monitor_degraded"},
	}
}

// classifyManualCert returns the severity, phase label, and detail string for a
// cert row. Extracted for unit testing without a DB dependency.
// now is injected so tests can fix the reference time.
func classifyManualCert(now time.Time, notAfter time.Time, daysLeft int) (Severity, string, string) {
	if now.After(notAfter) {
		daysAgo := int(now.Sub(notAfter).Hours() / 24)
		detail := fmt.Sprintf("expired %d days ago (%s)", daysAgo, notAfter.UTC().Format("2006-01-02"))
		return SeverityCritical, "expired", detail
	}
	detail := fmt.Sprintf("expires in %d days (%s)", daysLeft, notAfter.UTC().Format("2006-01-02"))
	return SeverityWarning, "warn", detail
}

// highErrorRate fires for active routes with a 5xx ratio above the threshold
// within the rolling window. Severity escalates to Critical at >= 50% errors.
func highErrorRate(ctx context.Context, db *sql.DB, cfg Config) []Alert {
	rows, err := db.QueryContext(ctx, `
		SELECT hal.route_id, r.domain,
		       COUNT(*) AS total,
		       SUM(CASE WHEN hal.status >= 500 THEN 1 ELSE 0 END) AS errors
		  FROM host_access_log hal
		  JOIN routes r ON r.id = hal.route_id
		 WHERE hal.ts >= (NOW() - INTERVAL ? MINUTE)
		   AND r.status = 'active'
		 GROUP BY hal.route_id, r.domain
		HAVING total >= ? AND (errors / total) >= ?`,
		cfg.ErrorRateWindowMinutes, cfg.ErrorRateMinRequests, cfg.ErrorRatePct)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var routeID int64
		var domain string
		var total, errors int64
		if err := rows.Scan(&routeID, &domain, &total, &errors); err != nil {
			continue
		}
		ratio := float64(errors) / float64(total)
		sev := SeverityWarning
		if ratio >= 0.50 {
			sev = SeverityCritical
		}
		out = append(out, Alert{
			RuleID:   "high_error_rate",
			Severity: sev,
			Title:    fmt.Sprintf("High 5xx rate on %s", domain),
			Detail:   fmt.Sprintf("%d/%d reqs failed (%.0f%%) in last %dm", errors, total, ratio*100, cfg.ErrorRateWindowMinutes),
			Labels: map[string]string{
				"route_id":  strconv.FormatInt(routeID, 10),
				"domain":    domain,
				"error_pct": fmt.Sprintf("%.2f", ratio),
			},
		})
	}
	return out
}

// wafAttackSurge fires when the WAF blocks many requests on a single host
// within the rolling window. Fires once per host per cooldown window.
func wafAttackSurge(ctx context.Context, db *sql.DB, cfg Config) []Alert {
	window := cfg.WAFSurgeWindowMinutes
	if window <= 0 {
		window = 5
	}
	threshold := cfg.WAFSurgeThreshold
	if threshold <= 0 {
		threshold = 50
	}
	rows, err := db.QueryContext(ctx, `
		SELECT host, COUNT(*) AS blocks
		  FROM waf_events
		 WHERE ts >= (NOW() - INTERVAL ? MINUTE)
		   AND action = 'blocked'
		 GROUP BY host
		HAVING blocks >= ?
		 ORDER BY blocks DESC
		 LIMIT 10`,
		window, threshold)
	if err != nil {
		var me *mysql.MySQLError
		// Table not yet migrated - suppress false alert on first boot.
		if errors.As(err, &me) && me.Number == 1146 {
			return nil
		}
		return nil
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var host string
		var blocks int64
		if err := rows.Scan(&host, &blocks); err != nil {
			continue
		}
		out = append(out, Alert{
			RuleID:   "waf_attack_surge",
			Severity: SeverityCritical,
			Title:    fmt.Sprintf("WAF attack surge on %s", host),
			Detail:   fmt.Sprintf("%d blocked requests in last %dm", blocks, window),
			Labels:   map[string]string{"host": host, "blocks": strconv.FormatInt(blocks, 10)},
		})
	}
	return out
}

// KnownRuleIDs is the canonical rule list used by the admin filter UI.
func KnownRuleIDs() []string {
	return []string{"node_offline", "route_failed", "cert_failing", "wg_tunnel_stale", "db_pool_saturated", "drill_stale", "wg_key_not_fetched", "manual_cert_expiry", "high_error_rate", "waf_attack_surge"}
}

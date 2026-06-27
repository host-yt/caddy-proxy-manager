package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/alert"
)

type alertRow struct {
	ID       int64
	RuleID   string
	Severity string
	Title    string
	Detail   string
	Labels   string // raw labels JSON, rendered verbatim
	FiredAt  string
}

// alertRuleStatus aggregates 7-day activity for one known rule.
type alertRuleStatus struct {
	RuleID      string
	LastFired   *time.Time
	FireCount   int64
	Severity    string
	Description string
}

type alertsData struct {
	baseAdminData
	Rows            []alertRow
	RuleFilter      string
	KnownRules      []string
	RulesStatus     []alertRuleStatus
	AlertCfg        alert.Config
	ErrorRatePct100 int // AlertCfg.ErrorRatePct * 100, pre-computed for template
}

// ruleDescriptions maps each known rule_id to a short human description.
var ruleDescriptions = map[string]string{
	"node_offline":      "Node unhealthy and unseen past threshold",
	"route_failed":      "Route stuck in 'failed' state (SSL or DNS)",
	"cert_failing":      "Certificate stuck in pending_ssl past threshold",
	"wg_tunnel_stale":   "WG peer handshake older than threshold",
	"db_pool_saturated": "DB connection pool near saturation ratio",
	"drill_stale":       "No successful restore drill within configured days",
	"wg_key_not_fetched": "Bootstrap token unconsumed after key rotation grace period",
	"manual_cert_expiry": "Manually imported cert nearing expiry or already expired",
	"high_error_rate":   "5xx ratio above threshold in rolling window",
}

// AlertsPage handles GET /admin/alerts. Reads alert_log directly (same
// pattern as AuditList) - no pointer to the evaluator needed.
func (h *AdminHandlers) AlertsPage(w http.ResponseWriter, r *http.Request) {
	ruleFilter := strings.TrimSpace(r.URL.Query().Get("rule"))
	d := alertsData{
		baseAdminData:   h.base(r, "Alerts"),
		RuleFilter:      ruleFilter,
		KnownRules:      alert.KnownRuleIDs(),
		AlertCfg:        h.AlertCfg,
		ErrorRatePct100: int(h.AlertCfg.ErrorRatePct * 100),
	}
	db := h.DB()
	if db == nil {
		h.render(w, "alerts", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	q := `SELECT id, rule_id, severity, title, COALESCE(detail,''),
	             COALESCE(labels_json,'{}'), DATE_FORMAT(fired_at,'%Y-%m-%d %H:%i:%s')
	        FROM alert_log`
	args := []any{}
	if ruleFilter != "" {
		q += " WHERE rule_id = ?"
		args = append(args, ruleFilter)
	}
	q += " ORDER BY id DESC LIMIT 200"

	rows, err := db.QueryContext(ctx, q, args...)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var a alertRow
			if err := rows.Scan(&a.ID, &a.RuleID, &a.Severity, &a.Title, &a.Detail, &a.Labels, &a.FiredAt); err == nil {
				d.Rows = append(d.Rows, a)
			}
		}
	}

	// Query 7-day aggregate per rule_id from alert_log.
	type ruleAgg struct {
		lastFired *time.Time
		count     int64
		severity  string
	}
	agg := make(map[string]*ruleAgg)
	aggRows, err := db.QueryContext(ctx,
		`SELECT rule_id, MAX(fired_at), COUNT(*), COALESCE(MAX(severity),'info')
		   FROM alert_log
		  WHERE fired_at > (NOW() - INTERVAL 7 DAY)
		  GROUP BY rule_id`)
	if err == nil {
		defer aggRows.Close()
		for aggRows.Next() {
			var ruleID, sev string
			var lastFired time.Time
			var cnt int64
			if err := aggRows.Scan(&ruleID, &lastFired, &cnt, &sev); err == nil {
				t := lastFired
				agg[ruleID] = &ruleAgg{lastFired: &t, count: cnt, severity: sev}
			}
		}
	}

	// Build one status entry per known rule; never-fired rules have nil LastFired.
	for _, ruleID := range alert.KnownRuleIDs() {
		rs := alertRuleStatus{
			RuleID:      ruleID,
			Description: ruleDescriptions[ruleID],
		}
		if a, ok := agg[ruleID]; ok {
			rs.LastFired = a.lastFired
			rs.FireCount = a.count
			rs.Severity = a.severity
		}
		d.RulesStatus = append(d.RulesStatus, rs)
	}

	h.render(w, "alerts", d)
}

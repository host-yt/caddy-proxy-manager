package handlers

import (
	"context"
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/alert"
	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
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
	// Pagination over alert_log.
	Total    int
	TotalPgs int
	Page     int
	Size     int
	PrevURL  string
	NextURL  string
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
	"high_error_rate":    "5xx ratio above threshold in rolling window",
	"waf_attack_surge":   "WAF block count exceeded surge threshold within window",
}

// AlertsPage handles GET /admin/alerts. Reads alert_log directly (same
// pattern as AuditList) - no pointer to the evaluator needed.
func (h *AdminHandlers) AlertsPage(w http.ResponseWriter, r *http.Request) {
	ruleFilter := strings.TrimSpace(r.URL.Query().Get("rule"))
	lp := parseListParams(r, []string{"id"}, "id", "desc", 50)
	d := alertsData{
		baseAdminData:   h.base(r, "Alerts"),
		RuleFilter:      ruleFilter,
		KnownRules:      alert.KnownRuleIDs(),
		AlertCfg:        h.AlertCfg,
		ErrorRatePct100: int(h.AlertCfg.ErrorRatePct * 100),
		Page:            lp.Page,
		Size:            lp.Size,
	}
	db := h.DB()
	if db == nil {
		h.render(w, "alerts", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	where := ""
	args := []any{}
	if ruleFilter != "" {
		where = " WHERE rule_id = ?"
		args = append(args, ruleFilter)
	}

	// Total count for pagination (ignores limit/offset).
	var total int
	countArgs := make([]any, len(args))
	copy(countArgs, args)
	if cerr := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM alert_log"+where, countArgs...).Scan(&total); cerr != nil {
		h.Logger.Warn("alerts count query", "err", cerr)
	}

	q := `SELECT id, rule_id, severity, title, COALESCE(detail,''),
	             COALESCE(labels_json,'{}'), DATE_FORMAT(fired_at,'%Y-%m-%d %H:%i:%s')
	        FROM alert_log` + where + ` ORDER BY id DESC LIMIT ? OFFSET ?`
	args = append(args, lp.Size, lp.Offset())

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

	// Count fallback: if COUNT failed but rows loaded, use lower bound so
	// pagination controls still render.
	if total == 0 && len(d.Rows) > 0 {
		total = lp.Offset() + len(d.Rows)
	}
	d.Total = total
	d.TotalPgs = (total + lp.Size - 1) / lp.Size
	if d.TotalPgs < 1 {
		d.TotalPgs = 1
	}
	qv := r.URL.Query()
	if lp.Page > 1 {
		d.PrevURL = buildPageURL(qv, lp.Page-1)
	}
	if lp.Page < d.TotalPgs {
		d.NextURL = buildPageURL(qv, lp.Page+1)
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

// AlertsClear handles POST /admin/alerts/clear. Purges the entire alert log.
// Restricted to super_admin; CSRF enforced by middleware.
func (h *AdminHandlers) AlertsClear(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	if sess == nil || sess.Role != "super_admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, "/admin/alerts", "", "database unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	res, err := db.ExecContext(ctx, "DELETE FROM alert_log")
	if err != nil {
		h.Logger.Error("alerts clear", "err", err)
		redirectWithFlash(w, r, "/admin/alerts", "", "clear failed")
		return
	}
	n, _ := res.RowsAffected()
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess),
		Action: "alerts.cleared", Entity: "alert_log",
		Meta: map[string]any{"rows": n},
	})
	redirectWithFlash(w, r, "/admin/alerts", fmt.Sprintf("Cleared %d alerts", n), "")
}

// AlertsExport streams alert_log rows as CSV (last 5000, same filters as AlertsPage).
func (h *AdminHandlers) AlertsExport(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	ruleID := r.URL.Query().Get("rule_id")
	since := r.URL.Query().Get("since")

	where := []string{"1=1"}
	args := []any{}
	if ruleID != "" {
		where = append(where, "rule_id = ?")
		args = append(args, ruleID)
	}
	if since != "" {
		where = append(where, "fired_at >= ?")
		args = append(args, since)
	}
	args = append(args, 5000)

	rows, err := db.QueryContext(ctx,
		"SELECT id, rule_id, severity, title, COALESCE(detail,''), DATE_FORMAT(fired_at,'%Y-%m-%dT%H:%i:%sZ') FROM alert_log WHERE "+
			strings.Join(where, " AND ")+" ORDER BY id DESC LIMIT ?",
		args...)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=alerts.csv")

	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"id", "rule_id", "severity", "title", "detail", "fired_at"})
	for rows.Next() {
		var id int64
		var rule, sev, title, detail, firedAt string
		if err := rows.Scan(&id, &rule, &sev, &title, &detail, &firedAt); err != nil {
			continue
		}
		_ = cw.Write(csvSafeRow([]string{strconv.FormatInt(id, 10), rule, sev, title, detail, firedAt}))
	}
	cw.Flush()
}

// AlertsTestFire handles POST /admin/alerts/test-fire - dispatches a manual test alert.
func (h *AdminHandlers) AlertsTestFire(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	if sess == nil || sess.Role != "super_admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	a := alert.Alert{
		RuleID:   "test_fire",
		Severity: alert.SeverityWarning,
		Title:    "HPG Alert Test",
		Detail:   "This is a test alert triggered by the admin. If you received it, all channels are working.",
		Labels:   map[string]string{"source": "manual_test"},
	}
	if h.AlertEval != nil {
		h.AlertEval.TestFire(r.Context(), a)
	}
	db := h.DB()
	if db != nil {
		audit.Write(r.Context(), db, h.Logger, r, audit.Entry{
			UserID: actorUserID(sess), Action: "admin.alert.test_fire", Entity: "alert", EntityID: "test_fire",
		})
	}
	redirectWithFlash(w, r, "/admin/alerts", "Test alert dispatched to all channels", "")
}

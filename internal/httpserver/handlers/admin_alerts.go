package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/hostyt/proxy-gateway/internal/alert"
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

type alertsData struct {
	baseAdminData
	Rows       []alertRow
	RuleFilter string
	KnownRules []string
}

// AlertsPage handles GET /admin/alerts. Reads alert_log directly (same
// pattern as AuditList) - no pointer to the evaluator needed.
func (h *AdminHandlers) AlertsPage(w http.ResponseWriter, r *http.Request) {
	ruleFilter := strings.TrimSpace(r.URL.Query().Get("rule"))
	d := alertsData{
		baseAdminData: h.base(r, "Alerts"),
		RuleFilter:    ruleFilter,
		KnownRules:    alert.KnownRuleIDs(),
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
	h.render(w, "alerts", d)
}

package handlers

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/wafevents"
)

// wafScopeOK authorizes a WAF query. Scoped admins (non-super_admin with scope
// enforcement active) must target a specific route they can access; the
// unfiltered "all routes" view stays limited to super_admin / single-admin.
func (h *AdminHandlers) wafScopeOK(ctx context.Context, sess *auth.Session, routeID int64) bool {
	if sess != nil && sess.Role != "super_admin" && h.AdminScope != nil {
		return routeID > 0 && h.scopeCheckRoute(ctx, sess, routeID)
	}
	return routeID <= 0 || h.scopeCheckRoute(ctx, sess, routeID)
}

// wafEventsData drives the waf_events template.
type wafEventsData struct {
	baseAdminData
	Entries []wafevents.Event
	Filter  wafevents.Filter
}

// parseWAFFilter reads WAF filter query params from r.
func parseWAFFilter(r *http.Request) wafevents.Filter {
	q := r.URL.Query()
	var f wafevents.Filter
	f.RouteID, _ = strconv.ParseInt(q.Get("route_id"), 10, 64)
	f.Severity = q.Get("severity")
	f.Action = q.Get("action")
	f.RuleID = q.Get("rule_id")
	f.Host = q.Get("host")
	f.RemoteIP = q.Get("remote_ip")
	if s := q.Get("from"); s != "" {
		f.From, _ = time.Parse("2006-01-02", s)
	}
	if s := q.Get("to"); s != "" {
		t, err := time.Parse("2006-01-02", s)
		if err == nil {
			f.To = t.Add(24*time.Hour - time.Second) // inclusive end of day
		}
	}
	return f
}

// hasWAFFilter reports whether any filter field is set.
func hasWAFFilter(f wafevents.Filter) bool {
	return f.RouteID > 0 || f.Severity != "" || f.Action != "" ||
		f.RuleID != "" || f.Host != "" || f.RemoteIP != "" ||
		!f.From.IsZero() || !f.To.IsZero()
}

// WafEvents renders GET /admin/waf.
func (h *AdminHandlers) WafEvents(w http.ResponseWriter, r *http.Request) {
	d := wafEventsData{baseAdminData: h.base(r, "WAF events")}
	if h.WAFEvents == nil {
		h.render(w, "waf_events", d)
		return
	}
	ctx := r.Context()
	sess := middleware.SessionFromContext(ctx)
	f := parseWAFFilter(r)

	// Scope: scoped admins must target a specific route they can access; the
	// unfiltered "all routes" view is restricted to super_admin / single-admin.
	if !h.wafScopeOK(ctx, sess, f.RouteID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	d.Filter = f

	var (
		entries []wafevents.Event
		err     error
	)
	if hasWAFFilter(f) {
		f.Limit = 200
		entries, err = h.WAFEvents.Filtered(ctx, f)
	} else {
		entries, err = h.WAFEvents.Recent(ctx, 0, 100)
	}
	if err != nil {
		h.Logger.Warn("waf events query", "err", err)
	}
	d.Entries = entries
	h.render(w, "waf_events", d)
}

// WafEventsJSON returns the last 100 events as JSON for GET /admin/waf.json.
func (h *AdminHandlers) WafEventsJSON(w http.ResponseWriter, r *http.Request) {
	if h.WAFEvents == nil {
		apiJSON(w, http.StatusOK, []any{})
		return
	}
	ctx := r.Context()
	sess := middleware.SessionFromContext(ctx)

	routeID, _ := strconv.ParseInt(r.URL.Query().Get("route_id"), 10, 64)
	if !h.wafScopeOK(ctx, sess, routeID) {
		apiJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}

	entries, err := h.WAFEvents.Recent(ctx, routeID, 100)
	if err != nil {
		h.Logger.Warn("waf events json", "err", err)
		apiJSON(w, http.StatusInternalServerError, map[string]string{"error": "query failed"})
		return
	}
	type row struct {
		ID       int64  `json:"id"`
		RouteID  *int64 `json:"route_id,omitempty"`
		TS       string `json:"ts"`
		Severity string `json:"severity"`
		RuleID   string `json:"rule_id"`
		Action   string `json:"action"`
		RemoteIP string `json:"remote_ip"`
		Host     string `json:"host"`
		URI      string `json:"uri"`
		Message  string `json:"message"`
	}
	out := make([]row, 0, len(entries))
	for _, e := range entries {
		r := row{
			ID:       e.ID,
			TS:       e.TS.UTC().Format(time.RFC3339Nano),
			Severity: e.Severity,
			RuleID:   e.RuleID,
			Action:   e.Action,
			RemoteIP: e.RemoteIP,
			Host:     e.Host,
			URI:      e.URI,
			Message:  e.Message,
		}
		if e.RouteID.Valid {
			v := e.RouteID.Int64
			r.RouteID = &v
		}
		out = append(out, r)
	}
	apiJSON(w, http.StatusOK, out)
}

// WafEventsExport serves GET /admin/waf/export?format=csv|json with optional filter params.
func (h *AdminHandlers) WafEventsExport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format != "csv" && format != "json" {
		format = "csv"
	}
	if h.WAFEvents == nil {
		http.Error(w, "not available", http.StatusServiceUnavailable)
		return
	}
	ctx := r.Context()
	sess := middleware.SessionFromContext(ctx)

	f := parseWAFFilter(r)
	if !h.wafScopeOK(ctx, sess, f.RouteID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Reuse the same per-session/IP export rate limiter as access logs.
	if !checkLogsExportRateLimit(logsExportLimiterKey(r, sess), time.Now()) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	f.Limit = wafevents.MaxExportRows
	entries, err := h.WAFEvents.Filtered(ctx, f)
	if err != nil {
		h.Logger.Warn("waf events export", "err", err)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}

	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess),
		Action: "waf_events.export", Entity: "waf_events",
		Meta: map[string]any{"format": format, "rows": len(entries)},
	})

	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="waf-events.csv"`)
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"id", "route_id", "ts", "severity", "rule_id", "action", "remote_ip", "host", "uri", "message"})
		for i, e := range entries {
			rid := ""
			if e.RouteID.Valid {
				rid = strconv.FormatInt(e.RouteID.Int64, 10)
			}
			_ = cw.Write(csvSafeRow([]string{
				strconv.FormatInt(e.ID, 10),
				rid,
				e.TS.UTC().Format(time.RFC3339Nano),
				e.Severity,
				e.RuleID,
				e.Action,
				e.RemoteIP,
				e.Host,
				e.URI,
				e.Message,
			}))
			if (i+1)%100 == 0 {
				cw.Flush()
			}
		}
		cw.Flush()
		return
	}

	// JSON export.
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="waf-events.json"`)
	type row struct {
		ID       int64  `json:"id"`
		RouteID  *int64 `json:"route_id,omitempty"`
		TS       string `json:"ts"`
		Severity string `json:"severity"`
		RuleID   string `json:"rule_id"`
		Action   string `json:"action"`
		RemoteIP string `json:"remote_ip"`
		Host     string `json:"host"`
		URI      string `json:"uri"`
		Message  string `json:"message"`
	}
	out := make([]row, 0, len(entries))
	for _, e := range entries {
		r := row{
			ID:       e.ID,
			TS:       e.TS.UTC().Format(time.RFC3339Nano),
			Severity: e.Severity,
			RuleID:   e.RuleID,
			Action:   e.Action,
			RemoteIP: e.RemoteIP,
			Host:     e.Host,
			URI:      e.URI,
			Message:  e.Message,
		}
		if e.RouteID.Valid {
			v := e.RouteID.Int64
			r.RouteID = &v
		}
		out = append(out, r)
	}
	enc := json.NewEncoder(w)
	_ = enc.Encode(out)
}

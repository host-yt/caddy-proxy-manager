package handlers

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/geoip"
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
	Entries      []wafevents.Event
	Filter       wafevents.Filter
	Suppressions []wafevents.Suppression
	// RouteDomain is non-empty when filtered to a specific route.
	RouteDomain string
	// ASNS maps remote_ip -> "AS12345 OrgName"; empty when ASN DB absent.
	ASNS map[string]string
	// Pagination metadata.
	Total    int
	TotalPgs int
	Page     int
	Size     int
	PrevURL  string
	NextURL  string
	// CanClear is true when the session may purge events (super_admin, or a
	// scoped admin viewing a single route they own).
	CanClear bool
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
	// Page size (rows per page). Default 50; ?limit=N changes it (capped). The
	// page view paginates; export overrides Limit to MaxExportRows separately.
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	if f.Limit <= 0 {
		f.Limit = 50
	} else if f.Limit > 1000 {
		f.Limit = 1000
	}
	return f
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

	// Pagination: page is 1-based; offset derives from the current page size.
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	f.Offset = (page - 1) * f.Limit
	d.Filter = f
	d.Page = page
	d.Size = f.Limit

	// Global clear requires super_admin; route-scoped clear requires a positive routeID.
	if sess != nil {
		if sess.Role == "super_admin" {
			d.CanClear = true
		} else if f.RouteID > 0 {
			d.CanClear = true
		}
	}

	// Look up domain for display when filtering by a specific route.
	if f.RouteID > 0 && h.DB != nil {
		if db := h.DB(); db != nil {
			_ = db.QueryRowContext(ctx, "SELECT domain FROM routes WHERE id = ?", f.RouteID).Scan(&d.RouteDomain)
		}
	}

	entries, _, err := h.WAFEvents.FilteredWithSuppressions(ctx, f)
	if err != nil {
		h.Logger.Warn("waf events query", "err", err)
	}
	d.Entries = entries

	// Total count for pagination (ignores limit/offset).
	total, cerr := h.WAFEvents.CountFiltered(ctx, f)
	if cerr != nil {
		h.Logger.Warn("waf events count", "err", cerr)
		// Fall back: count failed but entries loaded; use lower bound.
		total = f.Offset + len(entries)
	}
	d.Total = total
	d.TotalPgs = (total + f.Limit - 1) / f.Limit
	if d.TotalPgs < 1 {
		d.TotalPgs = 1
	}
	if page > 1 {
		d.PrevURL = buildPageURL(q, page-1)
	}
	if page < d.TotalPgs {
		d.NextURL = buildPageURL(q, page+1)
	}

	// Enrich entries with ASN data when the DB is available; skip silently if absent.
	if len(entries) > 0 {
		asnMap := make(map[string]string, len(entries))
		for _, e := range entries {
			if e.RemoteIP == "" {
				continue
			}
			if _, seen := asnMap[e.RemoteIP]; seen {
				continue
			}
			ip := net.ParseIP(e.RemoteIP)
			if ip == nil {
				continue
			}
			if asn, org, ok := geoip.LookupASN(ip); ok {
				asnMap[e.RemoteIP] = fmt.Sprintf("AS%d %s", asn, org)
			}
		}
		d.ASNS = asnMap
	}

	// Load active suppressions for display; scoped admins see only their routes'.
	var scopeRouteIDs []int64
	if sess != nil && sess.Role != "super_admin" && h.AdminScope != nil {
		// Scoped admin: only show their accessible route suppressions.
		scopeRouteIDs = []int64{}
		if f.RouteID > 0 {
			scopeRouteIDs = []int64{f.RouteID}
		}
	}
	sups, serr := h.WAFEvents.ListSuppressions(ctx, scopeRouteIDs)
	if serr != nil {
		h.Logger.Warn("waf suppressions query", "err", serr)
	}
	d.Suppressions = sups

	h.render(w, "waf_events", d)
}

// WAFSuppressRule handles POST /admin/waf/suppress.
// Creates a new rule suppression. Scoped admins may not create global ones.
func (h *AdminHandlers) WAFSuppressRule(w http.ResponseWriter, r *http.Request) {
	if h.WAFEvents == nil {
		http.Error(w, "not available", http.StatusServiceUnavailable)
		return
	}
	ctx := r.Context()
	sess := middleware.SessionFromContext(ctx)
	if sess == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	_ = r.ParseForm()
	ruleID := strings.TrimSpace(r.FormValue("rule_id"))
	if len(ruleID) > 128 {
		ruleID = ruleID[:128]
	}
	if ruleID == "" {
		redirectWithFlash(w, r, "/admin/waf", "", "rule_id is required")
		return
	}
	reason := strings.TrimSpace(r.FormValue("reason"))
	if len(reason) > 255 {
		reason = reason[:255]
	}

	routeID, _ := strconv.ParseInt(r.FormValue("route_id"), 10, 64)

	// Scoped admins must target a route they can access; they cannot create global suppressions.
	isScoped := sess.Role != "super_admin" && h.AdminScope != nil
	if isScoped {
		if routeID == 0 {
			redirectWithFlash(w, r, "/admin/waf", "", "scoped admin cannot create a global suppression")
			return
		}
		if !h.scopeCheckRoute(ctx, sess, routeID) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}

	var routeIDVal sql.NullInt64
	if routeID > 0 {
		routeIDVal = sql.NullInt64{Int64: routeID, Valid: true}
	}

	var expiresAt sql.NullTime
	if s := strings.TrimSpace(r.FormValue("expires_at")); s != "" {
		if t, err := time.Parse("2006-01-02", s); err == nil {
			expiresAt = sql.NullTime{Time: t.Add(24 * time.Hour), Valid: true}
		}
	}

	sup := wafevents.Suppression{
		RuleID:    ruleID,
		RouteID:   routeIDVal,
		Reason:    reason,
		CreatedBy: sess.UserID,
		ExpiresAt: expiresAt,
	}
	id, err := h.WAFEvents.SuppressRule(ctx, sup)
	if err != nil {
		h.Logger.Error("waf suppress rule", "err", err)
		redirectWithFlash(w, r, "/admin/waf", "", "could not save suppression")
		return
	}
	if h.DB != nil {
		audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
			UserID: actorUserID(sess),
			Action: "waf.rule_suppressed", Entity: "waf_rule_suppressions",
			EntityID: strconv.FormatInt(id, 10),
			Meta:     map[string]any{"rule_id": ruleID, "route_id": routeID, "reason": reason},
		})
	}
	redirectWithFlash(w, r, "/admin/waf", "Rule suppressed", "")
}

// WAFDeleteSuppression handles POST /admin/waf/suppressions/{id}/delete.
func (h *AdminHandlers) WAFDeleteSuppression(w http.ResponseWriter, r *http.Request) {
	if h.WAFEvents == nil {
		http.Error(w, "not available", http.StatusServiceUnavailable)
		return
	}
	ctx := r.Context()
	sess := middleware.SessionFromContext(ctx)
	if sess == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if id == 0 {
		redirectWithFlash(w, r, "/admin/waf", "", "invalid suppression id")
		return
	}

	// Scoped admins may only delete suppressions for their own routes.
	var ownerRouteID int64
	isScoped := sess.Role != "super_admin" && h.AdminScope != nil
	if isScoped {
		routeID, _ := strconv.ParseInt(r.FormValue("route_id"), 10, 64)
		if routeID == 0 || !h.scopeCheckRoute(ctx, sess, routeID) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		ownerRouteID = routeID
	}

	if err := h.WAFEvents.DeleteSuppression(ctx, id, ownerRouteID); err != nil {
		h.Logger.Error("waf delete suppression", "err", err)
		redirectWithFlash(w, r, "/admin/waf", "", "delete failed")
		return
	}
	if h.DB != nil {
		audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
			UserID: actorUserID(sess),
			Action: "waf.suppression_deleted", Entity: "waf_rule_suppressions",
			EntityID: strconv.FormatInt(id, 10),
		})
	}
	redirectWithFlash(w, r, "/admin/waf", "Suppression deleted", "")
}

// WAFAckEvent handles POST /admin/waf/events/{id}/ack.
func (h *AdminHandlers) WAFAckEvent(w http.ResponseWriter, r *http.Request) {
	if h.WAFEvents == nil {
		http.Error(w, "not available", http.StatusServiceUnavailable)
		return
	}
	ctx := r.Context()
	sess := middleware.SessionFromContext(ctx)
	if sess == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	eventID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if eventID == 0 {
		redirectWithFlash(w, r, "/admin/waf", "", "invalid event id")
		return
	}

	// Scope-check: verify the event belongs to a route this session can access.
	if !h.wafEventScopeOK(ctx, sess, eventID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if err := h.WAFEvents.AckEvent(ctx, eventID, sess.UserID); err != nil {
		h.Logger.Error("waf ack event", "err", err)
		redirectWithFlash(w, r, "/admin/waf", "", "ack failed")
		return
	}
	if h.DB != nil {
		audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
			UserID: actorUserID(sess),
			Action: "waf.event_acked", Entity: "waf_events",
			EntityID: strconv.FormatInt(eventID, 10),
		})
	}
	redirectWithFlash(w, r, "/admin/waf", "Event acknowledged", "")
}

// WAFClearEvents handles POST /admin/waf/events/clear. Super_admins purge all
// events (or one route when route_id is set); scoped admins may only purge a
// route they own. CSRF is enforced by middleware.
func (h *AdminHandlers) WAFClearEvents(w http.ResponseWriter, r *http.Request) {
	if h.WAFEvents == nil {
		http.Error(w, "not available", http.StatusServiceUnavailable)
		return
	}
	ctx := r.Context()
	sess := middleware.SessionFromContext(ctx)
	if sess == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	_ = r.ParseForm()
	routeID, _ := strconv.ParseInt(r.FormValue("route_id"), 10, 64)

	// Global purge (routeID==0) requires super_admin regardless of AdminScope.
	// Route-scoped purge requires a valid route the caller can access.
	if routeID == 0 {
		if sess.Role != "super_admin" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	} else if !h.scopeCheckRoute(ctx, sess, routeID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	n, err := h.WAFEvents.DeleteAll(ctx, routeID)
	if err != nil {
		h.Logger.Error("waf clear events", "err", err)
		redirectWithFlash(w, r, "/admin/waf", "", "clear failed")
		return
	}
	if h.DB != nil {
		audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
			UserID: actorUserID(sess),
			Action: "waf.events_cleared", Entity: "waf_events",
			Meta: map[string]any{"route_id": routeID, "rows": n},
		})
	}
	dest := "/admin/waf"
	if routeID > 0 {
		dest = "/admin/waf?route_id=" + strconv.FormatInt(routeID, 10)
	}
	redirectWithFlash(w, r, dest, fmt.Sprintf("Cleared %d events", n), "")
}

// wafEventScopeOK checks whether sess may act on the given event ID.
// Looks up the event's route_id and delegates to wafScopeOK.
func (h *AdminHandlers) wafEventScopeOK(ctx context.Context, sess *auth.Session, eventID int64) bool {
	if sess == nil {
		return false
	}
	if sess.Role == "super_admin" || h.AdminScope == nil {
		return true
	}
	if h.DB == nil {
		return false
	}
	db := h.DB()
	if db == nil {
		return false
	}
	var routeID sql.NullInt64
	if err := db.QueryRowContext(ctx,
		"SELECT route_id FROM waf_events WHERE id = ?", eventID,
	).Scan(&routeID); err != nil {
		return false
	}
	rid := int64(0)
	if routeID.Valid {
		rid = routeID.Int64
	}
	return h.wafScopeOK(ctx, sess, rid)
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

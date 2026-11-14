package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/routes"
	"github.com/host-yt/caddy-proxy-manager/internal/wafevents"
)

// Per-route WAF management over the REST API (#132). Reads follow the
// GET /routes/{id} boundary (owner client or in-scope admin); creating or
// lifting a suppression changes security policy and needs an admin key whose
// scope covers the route. Only route-scoped suppressions are reachable here:
// global ones stay a super_admin action in the panel.

const (
	apiWAFDefaultLimit = 50
	apiWAFMaxLimit     = 500
)

type apiWAFEvent struct {
	ID           int64      `json:"id"`
	RouteID      int64      `json:"route_id"`
	TS           time.Time  `json:"ts"`
	Severity     string     `json:"severity"`
	RuleID       string     `json:"rule_id"`
	Action       string     `json:"action"`
	RemoteIP     string     `json:"remote_ip"`
	Host         string     `json:"host"`
	URI          string     `json:"uri"`
	Message      string     `json:"message"`
	Suppressed   bool       `json:"suppressed"`
	Acknowledged bool       `json:"acknowledged"`
	AckedAt      *time.Time `json:"acknowledged_at,omitempty"`
}

type apiWAFSuppression struct {
	ID        int64      `json:"id"`
	RouteID   int64      `json:"route_id"`
	RuleID    string     `json:"rule_id"`
	Reason    string     `json:"reason"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at"`
}

func toAPIWAFSuppression(s wafevents.Suppression) apiWAFSuppression {
	out := apiWAFSuppression{ID: s.ID, RouteID: s.RouteID.Int64, RuleID: s.RuleID,
		Reason: s.Reason, CreatedAt: s.CreatedAt}
	if s.ExpiresAt.Valid {
		t := s.ExpiresAt.Time
		out.ExpiresAt = &t
	}
	return out
}

// parseAPITime accepts RFC 3339 or a bare date. endOfDay moves a bare date to
// its last second so `to=2026-11-08` includes that whole day.
func parseAPITime(v string, endOfDay bool) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, true
	}
	if t, err := time.Parse("2006-01-02", v); err == nil {
		if endOfDay {
			t = t.Add(24*time.Hour - time.Second)
		}
		return t, true
	}
	return time.Time{}, false
}

// RouteWAFEvents serves GET /api/v1/routes/{id}/waf-events.
// Query: limit (1-500, default 50), offset, severity, action, rule_id
// (substring), remote_ip, from, to (RFC 3339 or YYYY-MM-DD).
func (h *APIHandlers) RouteWAFEvents(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if !h.routeReadable(ctx, w, r, id) {
		return
	}
	q := r.URL.Query()
	f := wafevents.Filter{
		RouteID:  id,
		Severity: strings.TrimSpace(q.Get("severity")),
		Action:   strings.TrimSpace(q.Get("action")),
		RuleID:   strings.TrimSpace(q.Get("rule_id")),
		RemoteIP: strings.TrimSpace(q.Get("remote_ip")),
		Limit:    apiWAFDefaultLimit,
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > apiWAFMaxLimit {
			apiErr(w, http.StatusBadRequest, "limit must be 1-500")
			return
		}
		f.Limit = n
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			apiErr(w, http.StatusBadRequest, "offset must be >= 0")
			return
		}
		f.Offset = n
	}
	if v := q.Get("from"); v != "" {
		t, ok := parseAPITime(v, false)
		if !ok {
			apiErr(w, http.StatusBadRequest, "from must be RFC 3339 or YYYY-MM-DD")
			return
		}
		f.From = t
	}
	if v := q.Get("to"); v != "" {
		t, ok := parseAPITime(v, true)
		if !ok {
			apiErr(w, http.StatusBadRequest, "to must be RFC 3339 or YYYY-MM-DD")
			return
		}
		f.To = t
	}
	body := map[string]any{"waf_events": []apiWAFEvent{}, "total": 0, "limit": f.Limit, "offset": f.Offset}
	if h.WAFEvents == nil {
		apiJSON(w, http.StatusOK, body)
		return
	}
	events, _, err := h.WAFEvents.FilteredWithSuppressions(ctx, f)
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	total, err := h.WAFEvents.CountFiltered(ctx, f)
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	out := make([]apiWAFEvent, 0, len(events))
	for _, e := range events {
		ev := apiWAFEvent{ID: e.ID, RouteID: e.RouteID.Int64, TS: e.TS.UTC(), Severity: e.Severity,
			RuleID: e.RuleID, Action: e.Action, RemoteIP: e.RemoteIP, Host: e.Host, URI: e.URI,
			Message: e.Message, Suppressed: e.Suppressed, Acknowledged: e.AcknowledgedAt.Valid}
		if e.AcknowledgedAt.Valid {
			t := e.AcknowledgedAt.Time.UTC()
			ev.AckedAt = &t
		}
		out = append(out, ev)
	}
	body["waf_events"] = out
	body["total"] = total
	apiJSON(w, http.StatusOK, body)
}

// RouteWAFSuppressions serves GET /api/v1/routes/{id}/waf-suppressions: the
// active (unexpired) suppressions scoped to this route.
func (h *APIHandlers) RouteWAFSuppressions(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if !h.routeReadable(ctx, w, r, id) {
		return
	}
	out := []apiWAFSuppression{}
	if h.WAFEvents != nil {
		sups, err := h.WAFEvents.ListSuppressions(ctx, []int64{id})
		if err != nil {
			apiErr(w, http.StatusInternalServerError, "query failed")
			return
		}
		for _, s := range sups {
			out = append(out, toAPIWAFSuppression(s))
		}
	}
	apiJSON(w, http.StatusOK, map[string]any{"waf_suppressions": out})
}

// RouteWAFSuppressionCreate serves POST /api/v1/routes/{id}/waf-suppressions.
// Body: {"rule_id": "942100", "reason": "...", "expires_at": "2026-12-31"}.
func (h *APIHandlers) RouteWAFSuppressionCreate(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		apiErr(w, http.StatusForbidden, "admin role required")
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var in struct {
		RuleID    string `json:"rule_id"`
		Reason    string `json:"reason"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	ruleID := strings.TrimSpace(in.RuleID)
	if ruleID == "" || len(ruleID) > 128 {
		apiErr(w, http.StatusBadRequest, "rule_id is required (max 128 chars)")
		return
	}
	// Baked into node config as SecRuleRemoveById: a numeric id or range only.
	if !routes.ValidWAFRuleID(ruleID) {
		apiErr(w, http.StatusBadRequest, "rule_id must be a numeric id or range (e.g. 942100 or 942100-942199)")
		return
	}
	reason := strings.TrimSpace(in.Reason)
	if len(reason) > 255 {
		apiErr(w, http.StatusBadRequest, "reason max 255 chars")
		return
	}
	var expires sql.NullTime
	if v := strings.TrimSpace(in.ExpiresAt); v != "" {
		t, ok := parseAPITime(v, true)
		if !ok {
			apiErr(w, http.StatusBadRequest, "expires_at must be RFC 3339 or YYYY-MM-DD")
			return
		}
		if !t.After(time.Now()) {
			apiErr(w, http.StatusBadRequest, "expires_at must be in the future")
			return
		}
		expires = sql.NullTime{Time: t, Valid: true}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if !h.routeInScope(ctx, w, r, id) {
		return
	}
	if h.WAFEvents == nil {
		apiErr(w, http.StatusServiceUnavailable, "waf store not ready")
		return
	}
	uid := apiCallerID(r)
	sid, err := h.WAFEvents.SuppressRule(ctx, wafevents.Suppression{
		RuleID: ruleID, RouteID: sql.NullInt64{Int64: id, Valid: true},
		Reason: reason, CreatedBy: uid, ExpiresAt: expires,
	})
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "could not save suppression")
		return
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "waf.rule_suppressed", Entity: "waf_rule_suppressions",
		EntityID: strconv.FormatInt(sid, 10),
		Meta:     map[string]any{"rule_id": ruleID, "route_id": id, "reason": reason},
	})
	h.pushRouteWAF(id)
	out := apiWAFSuppression{ID: sid, RouteID: id, RuleID: ruleID, Reason: reason, CreatedAt: time.Now().UTC()}
	if expires.Valid {
		out.ExpiresAt = &expires.Time
	}
	apiJSON(w, http.StatusCreated, out)
}

// RouteWAFSuppressionDelete serves DELETE /api/v1/routes/{id}/waf-suppressions/{sid}
// and lets the WAF apply the rule to this route again.
func (h *APIHandlers) RouteWAFSuppressionDelete(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		apiErr(w, http.StatusForbidden, "admin role required")
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	sid, _ := strconv.ParseInt(chi.URLParam(r, "sid"), 10, 64)
	if sid <= 0 {
		apiErr(w, http.StatusBadRequest, "invalid suppression id")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if !h.routeInScope(ctx, w, r, id) {
		return
	}
	if h.WAFEvents == nil {
		apiErr(w, http.StatusServiceUnavailable, "waf store not ready")
		return
	}
	ok, err := h.WAFEvents.DeleteRouteSuppression(ctx, sid, id)
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	if !ok {
		apiErr(w, http.StatusNotFound, "suppression not found on this route")
		return
	}
	uid := apiCallerID(r)
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "waf.suppression_deleted", Entity: "waf_rule_suppressions",
		EntityID: strconv.FormatInt(sid, 10),
		Meta:     map[string]any{"route_id": id},
	})
	h.pushRouteWAF(id)
	apiJSON(w, http.StatusOK, map[string]any{"id": sid, "route_id": id, "deleted": true})
}

// pushRouteWAF re-pushes the nodes serving the route: suppressions are baked
// into its config as SecRuleRemoveById, so without a push the change waits for
// an unrelated route edit.
func (h *APIHandlers) pushRouteWAF(routeID int64) {
	if h.Routes == nil {
		return
	}
	h.Routes.SchedulePushForRoute(h.Routes.BackgroundCtx(), routeID)
}

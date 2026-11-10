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
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/wafevents"
)

// wafRouteGate runs the checks shared by every /routes/{id}/waf/* call: admin
// role, store present, route in the caller's scope. WAF policy is admin-only
// for API callers, same as the route PATCH.
func (h *APIHandlers) wafRouteGate(w http.ResponseWriter, r *http.Request) (int64, context.Context, context.CancelFunc, bool) {
	noop := func() {}
	// Panel keeps reseller/client-scoped admins out of /admin/waf; mirror that.
	if !h.requireGlobalAPIAdmin(w, r) {
		return 0, nil, noop, false
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	if id <= 0 || !h.routeInScope(ctx, w, r, id) {
		cancel()
		if id <= 0 {
			apiErr(w, http.StatusNotFound, "not found")
		}
		return 0, nil, noop, false
	}
	if h.WAFEvents == nil {
		cancel()
		apiErr(w, http.StatusServiceUnavailable, "waf events not available")
		return 0, nil, noop, false
	}
	return id, ctx, cancel, true
}

type apiWAFSuppression struct {
	ID        int64      `json:"id"`
	RuleID    string     `json:"rule_id"`
	RouteID   int64      `json:"route_id"`
	Reason    string     `json:"reason"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at"`
}

func toAPIWAFSuppression(s wafevents.Suppression) apiWAFSuppression {
	o := apiWAFSuppression{ID: s.ID, RuleID: s.RuleID, RouteID: s.RouteID.Int64, Reason: s.Reason, CreatedAt: s.CreatedAt}
	if s.ExpiresAt.Valid {
		t := s.ExpiresAt.Time
		o.ExpiresAt = &t
	}
	return o
}

// RouteWAFEvents serves GET /api/v1/routes/{id}/waf/events (newest first).
func (h *APIHandlers) RouteWAFEvents(w http.ResponseWriter, r *http.Request) {
	id, ctx, cancel, ok := h.wafRouteGate(w, r)
	if !ok {
		return
	}
	defer cancel()
	q := r.URL.Query()
	f := wafevents.Filter{RouteID: id, RuleID: q.Get("rule_id"), Action: q.Get("status")}
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	if f.Limit <= 0 {
		f.Limit = 50
	} else if f.Limit > 500 {
		f.Limit = 500
	}
	f.Offset, _ = strconv.Atoi(q.Get("offset"))
	if f.Offset < 0 {
		f.Offset = 0
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
	type row struct {
		ID             int64      `json:"id"`
		TS             time.Time  `json:"ts"`
		Severity       string     `json:"severity"`
		RuleID         string     `json:"rule_id"`
		Status         string     `json:"status"`
		RemoteIP       string     `json:"remote_ip"`
		Host           string     `json:"host"`
		URI            string     `json:"uri"`
		Message        string     `json:"message"`
		Suppressed     bool       `json:"suppressed"`
		AcknowledgedAt *time.Time `json:"acknowledged_at"`
	}
	out := make([]row, 0, len(events))
	for _, e := range events {
		x := row{e.ID, e.TS.UTC(), e.Severity, e.RuleID, e.Action, e.RemoteIP, e.Host, e.URI, e.Message, e.Suppressed, nil}
		if e.AcknowledgedAt.Valid {
			t := e.AcknowledgedAt.Time.UTC()
			x.AcknowledgedAt = &t
		}
		out = append(out, x)
	}
	apiJSON(w, http.StatusOK, map[string]any{"events": out, "total": total, "limit": f.Limit, "offset": f.Offset})
}

// RouteWAFSuppressionsList serves GET /api/v1/routes/{id}/waf/suppressions.
func (h *APIHandlers) RouteWAFSuppressionsList(w http.ResponseWriter, r *http.Request) {
	id, ctx, cancel, ok := h.wafRouteGate(w, r)
	if !ok {
		return
	}
	defer cancel()
	sups, err := h.WAFEvents.ListSuppressions(ctx, []int64{id})
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	out := make([]apiWAFSuppression, 0, len(sups))
	for _, s := range sups {
		out = append(out, toAPIWAFSuppression(s))
	}
	apiJSON(w, http.StatusOK, map[string]any{"suppressions": out})
}

// validWAFRuleID accepts a positive integer (CRS/Coraza rule ids).
func validWAFRuleID(s string) bool {
	n, err := strconv.ParseInt(s, 10, 64)
	return err == nil && n > 0 && strconv.FormatInt(n, 10) == s
}

// wafPush re-bakes SecRuleRemoveById into node configs after a change.
func (h *APIHandlers) wafPush() {
	if h.Routes != nil {
		h.Routes.SchedulePushAllNodes(h.Routes.BackgroundCtx())
	}
}

// RouteWAFSuppress serves POST /api/v1/routes/{id}/waf/suppressions. Always
// route-scoped; a global suppression is not reachable from here.
func (h *APIHandlers) RouteWAFSuppress(w http.ResponseWriter, r *http.Request) {
	id, ctx, cancel, ok := h.wafRouteGate(w, r)
	if !ok {
		return
	}
	defer cancel()
	var in struct {
		RuleID    json.Number `json:"rule_id"`
		Reason    string      `json:"reason"`
		ExpiresAt string      `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	ruleID := in.RuleID.String()
	if !validWAFRuleID(ruleID) {
		apiErr(w, http.StatusBadRequest, "rule_id must be a positive integer")
		return
	}
	reason := strings.TrimSpace(in.Reason)
	if rs := []rune(reason); len(rs) > 255 {
		reason = string(rs[:255])
	}
	var exp sql.NullTime
	if s := strings.TrimSpace(in.ExpiresAt); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			d, derr := time.Parse("2006-01-02", s)
			if derr != nil {
				apiErr(w, http.StatusBadRequest, "expires_at must be RFC3339 or YYYY-MM-DD")
				return
			}
			t = d.Add(24 * time.Hour) // date-only = end of that day, like the panel
		}
		if !t.After(time.Now()) {
			apiErr(w, http.StatusBadRequest, "expires_at must be in the future")
			return
		}
		exp = sql.NullTime{Time: t.UTC(), Valid: true}
	}
	// Idempotent: a retry returns the existing route-scoped row instead of a duplicate.
	if existing, lerr := h.WAFEvents.ListSuppressions(ctx, []int64{id}); lerr == nil {
		for _, s := range existing {
			if s.RuleID == ruleID && s.RouteID.Valid && s.RouteID.Int64 == id {
				apiJSON(w, http.StatusOK, map[string]any{"id": s.ID, "rule_id": ruleID, "route_id": id})
				return
			}
		}
	}
	c := middleware.CallerFromContext(r.Context())
	sid, err := h.WAFEvents.SuppressRule(ctx, wafevents.Suppression{
		RuleID: ruleID, RouteID: sql.NullInt64{Int64: id, Valid: true},
		Reason: reason, CreatedBy: c.UserID, ExpiresAt: exp,
	})
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "could not save suppression")
		return
	}
	uid := apiCallerID(r)
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "waf.rule_suppressed", Entity: "waf_rule_suppressions",
		EntityID: strconv.FormatInt(sid, 10),
		Meta:     map[string]any{"rule_id": ruleID, "route_id": id, "reason": reason},
	})
	h.wafPush()
	apiJSON(w, http.StatusCreated, map[string]any{"id": sid, "rule_id": ruleID, "route_id": id})
}

// RouteWAFUnsuppress serves DELETE /api/v1/routes/{id}/waf/suppressions/{rule_id}.
func (h *APIHandlers) RouteWAFUnsuppress(w http.ResponseWriter, r *http.Request) {
	id, ctx, cancel, ok := h.wafRouteGate(w, r)
	if !ok {
		return
	}
	defer cancel()
	// Panel stores free-form rule ids (<=128), so delete must accept them too.
	ruleID := strings.TrimSpace(chi.URLParam(r, "rule_id"))
	if ruleID == "" || len(ruleID) > 128 {
		apiErr(w, http.StatusBadRequest, "invalid rule_id")
		return
	}
	n, err := h.WAFEvents.DeleteRouteSuppressionsByRule(ctx, id, ruleID)
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	if n == 0 {
		apiErr(w, http.StatusNotFound, "no such suppression")
		return
	}
	uid := apiCallerID(r)
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "waf.suppression_deleted", Entity: "waf_rule_suppressions",
		EntityID: ruleID, Meta: map[string]any{"rule_id": ruleID, "route_id": id},
	})
	h.wafPush()
	apiJSON(w, http.StatusOK, map[string]any{"rule_id": ruleID, "route_id": id, "deleted": true})
}

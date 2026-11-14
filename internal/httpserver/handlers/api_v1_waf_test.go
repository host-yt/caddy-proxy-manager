package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/routes"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/wafevents"
)

func patchRoute7As(t *testing.T, db *sql.DB, role, body string) *httptest.ResponseRecorder {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := &APIHandlers{DB: func() *sql.DB { return db }, Logger: logger,
		Routes: &routes.Service{DB: db, Logger: logger}}
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/routes/7", strings.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "7")
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = middleware.ContextWithAPICaller(ctx, &middleware.APICaller{UserID: 1, Role: role})
	rec := httptest.NewRecorder()
	h.RouteUpdate(rec, req.WithContext(ctx))
	return rec
}

// #132: upstream_skip_tls_verify is settable over the API, returned by GET,
// and enabling it is a super_admin action exactly like in the panel.
func TestAPIRouteUpdate_UpstreamSkipTLSVerify(t *testing.T) {
	db := mtlsTLSEditDB(t)
	stored := func() bool {
		var v bool
		if err := db.QueryRow("SELECT COALESCE(upstream_skip_tls_verify,0) FROM routes WHERE id = 7").Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	if rec := patchRoute7As(t, db, "admin", `{"upstream_skip_tls_verify":true}`); rec.Code != http.StatusForbidden {
		t.Fatalf("plain admin enable: %d, want 403", rec.Code)
	}
	if stored() {
		t.Fatal("refused request still wrote the flag")
	}
	if rec := patchRoute7As(t, db, "super_admin", `{"upstream_scheme":"https","upstream_skip_tls_verify":true}`); rec.Code != http.StatusOK {
		t.Fatalf("super_admin enable: %d %s", rec.Code, rec.Body.String())
	}
	if !stored() {
		t.Fatal("flag not stored")
	}
	// Omitted = unchanged.
	if rec := patchRoute7As(t, db, "super_admin", `{"websocket":true}`); rec.Code != http.StatusOK {
		t.Fatalf("unrelated patch: %d", rec.Code)
	}
	if !stored() {
		t.Fatal("omitted field cleared the flag")
	}

	// GET returns it.
	h := &APIHandlers{DB: func() *sql.DB { return db }}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/routes/7", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "7")
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = middleware.ContextWithAPICaller(ctx, &middleware.APICaller{UserID: 1, Role: "super_admin"})
	rec := httptest.NewRecorder()
	h.RouteGet(rec, req.WithContext(ctx))
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if got["upstream_skip_tls_verify"] != true {
		t.Fatalf("GET upstream_skip_tls_verify = %v", got["upstream_skip_tls_verify"])
	}

	// Turning it off is the safe direction: any admin may.
	if rec := patchRoute7As(t, db, "admin", `{"upstream_skip_tls_verify":false}`); rec.Code != http.StatusOK {
		t.Fatalf("admin disable: %d %s", rec.Code, rec.Body.String())
	}
	if stored() {
		t.Fatal("disable not stored")
	}
}

func TestRoutePolicyJSON_SkipTLS(t *testing.T) {
	on, off := true, false
	if !(routePolicyJSON{UpstreamSkipTLS: &off}).hasPolicy() {
		t.Error("skip tls not counted as policy (clients must be refused)")
	}
	for role, want := range map[string]bool{"super_admin": true, "admin": false, "reseller": false, "client": false} {
		if got := (routePolicyJSON{UpstreamSkipTLS: &on}).skipTLSAllowed(&middleware.APICaller{Role: role}); got != want {
			t.Errorf("enable as %s = %v, want %v", role, got, want)
		}
		if !(routePolicyJSON{UpstreamSkipTLS: &off}).skipTLSAllowed(&middleware.APICaller{Role: role}) {
			t.Errorf("disable as %s refused", role)
		}
	}
}

func wafAPIDB(t *testing.T) *sql.DB {
	t.Helper()
	db := mtlsTLSEditDB(t)
	for _, s := range []string{
		`INSERT INTO users (id, email, password_hash, role) VALUES (2, 'o@b.c', 'x', 'client')`,
		`INSERT INTO clients (id, user_id, display_name) VALUES (2, 2, 'other')`,
		`INSERT INTO waf_events (id, route_id, ts, severity, rule_id, action, host, uri)
		   VALUES (1, 7, '2026-11-01 10:00:00', 'critical', '942100', 'blocked', 'locked.example', '/a'),
		          (2, 7, '2026-11-02 10:00:00', 'low', '920350', 'detected', 'locked.example', '/b'),
		          (3, 99, '2026-11-02 10:00:00', 'low', '942100', 'detected', 'x.example', '/c')`,
		`INSERT INTO waf_rule_suppressions (id, rule_id, route_id, reason, created_by)
		   VALUES (10, '999999', NULL, 'global', 1)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("seed %q: %v", s, err)
		}
	}
	return db
}

func wafCall(t *testing.T, db *sql.DB, fn func(*APIHandlers) http.HandlerFunc, method, target, body string,
	uid int64, role string, params map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := &APIHandlers{DB: func() *sql.DB { return db }, Logger: logger,
		WAFEvents: wafevents.New(func() *sql.DB { return db })}
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	rctx := chi.NewRouteContext()
	for k, v := range params {
		rctx.URLParams.Add(k, v)
	}
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = middleware.ContextWithAPICaller(ctx, &middleware.APICaller{UserID: uid, Role: role})
	rec := httptest.NewRecorder()
	fn(h)(rec, req.WithContext(ctx))
	return rec
}

func TestAPIRouteWAFEvents(t *testing.T) {
	db := wafAPIDB(t)
	events := func(h *APIHandlers) http.HandlerFunc { return h.RouteWAFEvents }
	p := map[string]string{"id": "7"}

	rec := wafCall(t, db, events, http.MethodGet, "/api/v1/routes/7/waf-events", "", 1, "super_admin", p)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Events []apiWAFEvent `json:"waf_events"`
		Total  int           `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Total != 2 || len(out.Events) != 2 || out.Events[0].ID != 2 {
		t.Fatalf("route filter/order wrong: total=%d events=%+v", out.Total, out.Events)
	}

	rec = wafCall(t, db, events, http.MethodGet, "/api/v1/routes/7/waf-events?severity=critical&limit=1&offset=0", "", 1, "super_admin", p)
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Total != 1 || len(out.Events) != 1 || out.Events[0].RuleID != "942100" {
		t.Fatalf("severity filter: %+v", out)
	}

	if c := wafCall(t, db, events, http.MethodGet, "/api/v1/routes/7/waf-events?limit=0", "", 1, "super_admin", p).Code; c != http.StatusBadRequest {
		t.Errorf("limit=0: %d, want 400", c)
	}
	if c := wafCall(t, db, events, http.MethodGet, "/api/v1/routes/7/waf-events?from=yesterday", "", 1, "super_admin", p).Code; c != http.StatusBadRequest {
		t.Errorf("bad from: %d, want 400", c)
	}
	if c := wafCall(t, db, events, http.MethodGet, "/api/v1/routes/7/waf-events", "", 1, "client", p).Code; c != http.StatusOK {
		t.Errorf("owner client: %d, want 200", c)
	}
	if c := wafCall(t, db, events, http.MethodGet, "/api/v1/routes/7/waf-events", "", 2, "client", p).Code; c != http.StatusForbidden {
		t.Errorf("other tenant: %d, want 403", c)
	}
}

func TestAPIRouteWAFSuppressions_CreateListDelete(t *testing.T) {
	db := wafAPIDB(t)
	create := func(h *APIHandlers) http.HandlerFunc { return h.RouteWAFSuppressionCreate }
	list := func(h *APIHandlers) http.HandlerFunc { return h.RouteWAFSuppressions }
	del := func(h *APIHandlers) http.HandlerFunc { return h.RouteWAFSuppressionDelete }
	p := map[string]string{"id": "7"}

	// Clients may not change WAF policy, even on their own route.
	if c := wafCall(t, db, create, http.MethodPost, "/", `{"rule_id":"942100"}`, 1, "client", p).Code; c != http.StatusForbidden {
		t.Errorf("client create: %d, want 403", c)
	}
	for _, body := range []string{`{}`, `{"rule_id":"942100\nSecRuleEngine Off"}`, `{"rule_id":"abc"}`,
		`{"rule_id":"942100","expires_at":"2000-01-01"}`, `{"rule_id":"942100","expires_at":"soon"}`} {
		if c := wafCall(t, db, create, http.MethodPost, "/", body, 1, "super_admin", p).Code; c != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", body, c)
		}
	}
	if c := wafCall(t, db, create, http.MethodPost, "/", `{"rule_id":"942100"}`, 1, "super_admin",
		map[string]string{"id": "404"}).Code; c != http.StatusNotFound {
		t.Errorf("missing route: %d, want 404", c)
	}

	rec := wafCall(t, db, create, http.MethodPost, "/", `{"rule_id":"942100","reason":"false positive","expires_at":"2099-01-01"}`, 1, "super_admin", p)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created apiWAFSuppression
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created.ID == 0 || created.RouteID != 7 || created.ExpiresAt == nil {
		t.Fatalf("created = %+v", created)
	}

	// The event for that rule now reads as suppressed.
	rec = wafCall(t, db, func(h *APIHandlers) http.HandlerFunc { return h.RouteWAFEvents },
		http.MethodGet, "/?rule_id=942100", "", 1, "super_admin", p)
	if !strings.Contains(rec.Body.String(), `"suppressed":true`) {
		t.Errorf("event not marked suppressed: %s", rec.Body.String())
	}

	rec = wafCall(t, db, list, http.MethodGet, "/", "", 1, "client", p)
	var listed struct {
		Sups []apiWAFSuppression `json:"waf_suppressions"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &listed)
	if rec.Code != http.StatusOK || len(listed.Sups) != 1 || listed.Sups[0].ID != created.ID {
		t.Fatalf("list (global must be excluded): %d %s", rec.Code, rec.Body.String())
	}

	sid := map[string]string{"id": "7", "sid": "10"}
	if c := wafCall(t, db, del, http.MethodDelete, "/", "", 1, "super_admin", sid).Code; c != http.StatusNotFound {
		t.Errorf("deleting a global suppression via a route: %d, want 404", c)
	}
	var n int
	_ = db.QueryRow("SELECT COUNT(*) FROM waf_rule_suppressions WHERE id = 10").Scan(&n)
	if n != 1 {
		t.Fatal("global suppression was removed through the per-route endpoint")
	}

	own := map[string]string{"id": "7", "sid": jsonID(created.ID)}
	if c := wafCall(t, db, del, http.MethodDelete, "/", "", 1, "client", own).Code; c != http.StatusForbidden {
		t.Errorf("client delete: %d, want 403", c)
	}
	if c := wafCall(t, db, del, http.MethodDelete, "/", "", 1, "super_admin", own).Code; c != http.StatusOK {
		t.Fatalf("delete: %d", c)
	}
	if c := wafCall(t, db, del, http.MethodDelete, "/", "", 1, "super_admin", own).Code; c != http.StatusNotFound {
		t.Errorf("second delete: %d, want 404", c)
	}
}

func jsonID(id int64) string { b, _ := json.Marshal(id); return string(b) }

func TestRestoreTargets(t *testing.T) {
	route := func(id int64) sql.NullInt64 { return sql.NullInt64{Int64: id, Valid: true} }
	events := []wafevents.Event{
		{ID: 1, RouteID: route(7), RuleID: "942100", Suppressed: true},
		{ID: 2, RouteID: route(8), RuleID: "942100", Suppressed: true},
		{ID: 3, RouteID: route(7), RuleID: "920350", Suppressed: false},
		{ID: 4, RouteID: route(9), RuleID: "111111", Suppressed: true},
	}
	sups := []wafevents.Suppression{
		{ID: 50, RuleID: "942100"},                    // global
		{ID: 51, RuleID: "942100", RouteID: route(7)}, // route 7
	}
	got := restoreTargets(events, sups)
	if got[1].ID != 51 {
		t.Errorf("route-scoped match should win: %+v", got[1])
	}
	if got[2].ID != 50 {
		t.Errorf("global fallback: %+v", got[2])
	}
	if _, ok := got[3]; ok {
		t.Error("unsuppressed event got a restore target")
	}
	if _, ok := got[4]; ok {
		t.Error("event with no visible suppression got a restore target")
	}
}

// #132: a suppressed event on /admin/waf offers "Restore rule", which posts to
// the delete endpoint of the suppression that silences it.
func TestWafEventsPage_RestoreRuleAction(t *testing.T) {
	db := wafAPIDB(t)
	if _, err := db.Exec(`INSERT INTO waf_rule_suppressions (id, rule_id, route_id, reason, created_by)
		VALUES (11, '942100', 7, 'fp', 1)`); err != nil {
		t.Fatal(err)
	}
	h := editFormHandlers(t, db)
	h.WAFEvents = wafevents.New(func() *sql.DB { return db })
	req := httptest.NewRequest(http.MethodGet, "/admin/waf?route_id=7", nil)
	ctx := middleware.ContextWithSession(req.Context(), &auth.Session{UserID: 1, Role: "super_admin"})
	rec := httptest.NewRecorder()
	h.WafEvents(rec, req.WithContext(ctx))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `action="/admin/waf/suppressions/11/delete" class="contents"`) {
		t.Fatal("suppressed event has no restore action for suppression 11")
	}
	if n := strings.Count(body, "Restore rule (delete suppression)"); n != 1 {
		t.Fatalf("restore actions = %d, want 1 (only the suppressed 942100 event)", n)
	}
}

// A suppressed event with no suppression the viewer may delete (scoped admin
// on the unfiltered view, or a global one) must not get a dead restore button
// posting to /suppressions/0/delete.
func TestWafEventsPage_NoRestoreWithoutTarget(t *testing.T) {
	h := editFormHandlers(t, wafAPIDB(t))
	d := wafEventsData{baseAdminData: h.base(httptest.NewRequest(http.MethodGet, "/admin/waf", nil), "WAF events")}
	d.Entries = []wafevents.Event{{ID: 1, RuleID: "942100", Suppressed: true}}
	d.TotalPgs, d.Page, d.Size = 1, 1, 50
	rec := httptest.NewRecorder()
	h.render(rec, "waf_events", d)
	if strings.Contains(rec.Body.String(), "Restore rule") || strings.Contains(rec.Body.String(), "/suppressions/0/delete") {
		t.Fatal("restore action rendered without a deletable suppression")
	}
}

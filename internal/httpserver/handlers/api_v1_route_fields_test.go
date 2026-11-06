package handlers

import (
	"context"
	"database/sql"
	"net/http/httptest"

	"github.com/go-chi/chi/v5"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"net/http"
	"testing"
)

// #118: upstream_scheme is validated, applied, and left alone when omitted.
func TestAPIRouteUpdate_UpstreamScheme(t *testing.T) {
	db := mtlsTLSEditDB(t)
	scheme := func() string {
		var s string
		if err := db.QueryRow("SELECT upstream_scheme FROM routes WHERE id = 7").Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	if rec := patchRoute7(t, db, `{"upstream_scheme":"ftp"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("bad scheme: status %d, want 400", rec.Code)
	}
	if rec := patchRoute7(t, db, `{"upstream_scheme":"https"}`); rec.Code != http.StatusOK {
		t.Fatalf("https: %d %s", rec.Code, rec.Body.String())
	}
	if scheme() != "https" {
		t.Errorf("scheme = %q, want https", scheme())
	}
	if rec := patchRoute7(t, db, `{"websocket":true}`); rec.Code != http.StatusOK {
		t.Fatalf("unrelated patch: %d", rec.Code)
	}
	if scheme() != "https" {
		t.Errorf("omitted scheme changed to %q", scheme())
	}
}

// #117: WAF / rate-limit toggles obey the node-module gate and the GUI validation.
func TestAPIRouteUpdate_WAFAndRateLimit(t *testing.T) {
	db := mtlsTLSEditDB(t)
	// Declared node without the modules: enabling must be refused.
	if _, err := db.Exec(`UPDATE caddy_nodes SET modules_probed_at = CURRENT_TIMESTAMP, has_waf = 0, has_rate_limit = 0
		WHERE id = (SELECT caddy_node_id FROM routes WHERE id = 7)`); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{"waf_enabled":true}`, `{"rate_limit_enabled":true}`,
		`{"rate_limit_window":"nope"}`, `{"rate_limit_max_events":2000000}`} {
		if rec := patchRoute7(t, db, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", body, rec.Code)
		}
	}
	var waf, rate int
	_ = db.QueryRow("SELECT waf_enabled, rate_enabled FROM routes WHERE id = 7").Scan(&waf, &rate)
	if waf != 0 || rate != 0 {
		t.Fatalf("refused request still wrote waf=%d rate=%d", waf, rate)
	}
	// Modules present: accepted and persisted, defaults applied for window/key.
	if _, err := db.Exec(`UPDATE caddy_nodes SET has_waf = 1, has_rate_limit = 1`); err != nil {
		t.Fatal(err)
	}
	if rec := patchRoute7(t, db, `{"waf_enabled":true,"waf_blocking":true,"rate_limit_enabled":true,"rate_limit_max_events":50}`); rec.Code != http.StatusOK {
		t.Fatalf("enable: %d %s", rec.Code, rec.Body.String())
	}
	var blocking, max int
	var win, key string
	if err := db.QueryRow("SELECT waf_enabled, waf_blocking, rate_enabled, rate_window, rate_max_events, rate_key FROM routes WHERE id = 7").
		Scan(&waf, &blocking, &rate, &win, &max, &key); err != nil {
		t.Fatal(err)
	}
	if waf != 1 || blocking != 1 || rate != 1 || win != "1m" || max != 50 || key != "{http.request.remote.host}" {
		t.Errorf("stored waf=%d blocking=%d rate=%d win=%q max=%d key=%q", waf, blocking, rate, win, max, key)
	}
	// Disabling never needs the module.
	if rec := patchRoute7(t, db, `{"waf_enabled":false}`); rec.Code != http.StatusOK {
		t.Errorf("disable: %d", rec.Code)
	}
}

func TestRoutePolicyJSON_HasPolicy(t *testing.T) {
	if (routePolicyJSON{}).hasPolicy() {
		t.Error("empty policy reported as set")
	}
	b := true
	if !(routePolicyJSON{WAFEnabled: &b}).hasPolicy() {
		t.Error("waf_enabled not detected")
	}
}

// IDOR: access logs follow the route's tenant boundary.
func TestAPIRouteAccessLogs_Scoping(t *testing.T) {
	db := mtlsTLSEditDB(t)
	if _, err := db.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES (2, 'o@b.c', 'x', 'client')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO clients (id, user_id, display_name) VALUES (2, 2, 'other')`); err != nil {
		t.Fatal(err)
	}
	h := &APIHandlers{DB: func() *sql.DB { return db }}
	get := func(uid int64, role string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/routes/7/access-logs", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", "7")
		ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
		ctx = middleware.ContextWithAPICaller(ctx, &middleware.APICaller{UserID: uid, Role: role})
		rec := httptest.NewRecorder()
		h.RouteAccessLogs(rec, req.WithContext(ctx))
		return rec.Code
	}
	if c := get(1, "client"); c != http.StatusOK {
		t.Errorf("owner: %d, want 200", c)
	}
	if c := get(2, "client"); c != http.StatusForbidden {
		t.Errorf("other tenant: %d, want 403", c)
	}
}

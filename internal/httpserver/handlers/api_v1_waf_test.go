package handlers

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/adminscope"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/routes"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/wafevents"
)

// scopedAdminDB adds a restricted admin (user 2, no clients) and a plain admin (3).
func scopedAdminDB(t *testing.T) *sql.DB {
	t.Helper()
	db := mtlsTLSEditDB(t)
	if _, err := db.Exec(`INSERT INTO users (id, email, password_hash, role, is_restricted) VALUES (2, 's@b.c', 'x', 'admin', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES (3, 'p@b.c', 'x', 'admin')`); err != nil {
		t.Fatal(err)
	}
	return db
}

func apiCall(db *sql.DB, fn func(*APIHandlers) http.HandlerFunc, method, body, routeID, ruleID string, c *middleware.APICaller) *httptest.ResponseRecorder {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := &APIHandlers{DB: func() *sql.DB { return db }, Logger: logger,
		Routes:     &routes.Service{DB: db, Logger: logger},
		AdminScope: adminscope.New(func() *sql.DB { return db }),
		WAFEvents:  wafevents.New(func() *sql.DB { return db })}
	req := httptest.NewRequest(method, "/api/v1/routes/"+routeID, strings.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", routeID)
	rctx.URLParams.Add("rule_id", ruleID)
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = middleware.ContextWithAPICaller(ctx, c)
	rec := httptest.NewRecorder()
	fn(h)(rec, req.WithContext(ctx))
	return rec
}

func TestAPIRouteUpdate_SkipTLSGate(t *testing.T) {
	db := scopedAdminDB(t)
	skip := func() int {
		var v int
		if err := db.QueryRow("SELECT upstream_skip_tls_verify FROM routes WHERE id = 7").Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	patch := func(body string, c *middleware.APICaller) *httptest.ResponseRecorder {
		return apiCall(db, func(h *APIHandlers) http.HandlerFunc { return h.RouteUpdate }, http.MethodPatch, body, "7", "", c)
	}
	// Plain admin may not enable it, even on an in-scope route.
	if rec := patch(`{"upstream_skip_tls_verify":true}`, &middleware.APICaller{UserID: 3, Role: "admin"}); rec.Code != http.StatusForbidden {
		t.Errorf("admin enable: %d, want 403", rec.Code)
	}
	if skip() != 0 {
		t.Fatal("denied request wrote the flag")
	}
	if rec := patch(`{"upstream_skip_tls_verify":true}`, &middleware.APICaller{UserID: 1, Role: "super_admin"}); rec.Code != http.StatusOK {
		t.Fatalf("super_admin enable: %d %s", rec.Code, rec.Body.String())
	}
	if skip() != 1 {
		t.Fatal("flag not stored")
	}
	// Absent field leaves it alone, for any admin.
	if rec := patch(`{"websocket":true}`, &middleware.APICaller{UserID: 3, Role: "admin"}); rec.Code != http.StatusOK {
		t.Fatalf("unrelated patch: %d %s", rec.Code, rec.Body.String())
	}
	if skip() != 1 {
		t.Error("absent field changed the flag")
	}
	// Disabling is the safe direction: open to a plain admin.
	if rec := patch(`{"upstream_skip_tls_verify":false}`, &middleware.APICaller{UserID: 3, Role: "admin"}); rec.Code != http.StatusOK {
		t.Fatalf("admin disable: %d", rec.Code)
	}
	if skip() != 0 {
		t.Error("flag not cleared")
	}
	// GET reports it.
	var rt apiRoute
	if err := scanRoute(db.QueryRow("SELECT "+routeSelectCols+" FROM routes r WHERE r.id = 7"), &rt); err != nil || rt.UpstreamSkipTLS {
		t.Errorf("scan: err=%v skip=%v", err, rt.UpstreamSkipTLS)
	}
}

func TestAPIRouteWAF_ScopeAndFlow(t *testing.T) {
	db := scopedAdminDB(t)
	super := &middleware.APICaller{UserID: 1, Role: "super_admin"}
	scoped := &middleware.APICaller{UserID: 2, Role: "admin"}
	type call struct {
		name   string
		fn     func(*APIHandlers) http.HandlerFunc
		method string
		body   string
	}
	for _, c := range []call{
		{"events", func(h *APIHandlers) http.HandlerFunc { return h.RouteWAFEvents }, http.MethodGet, ""},
		{"list", func(h *APIHandlers) http.HandlerFunc { return h.RouteWAFSuppressionsList }, http.MethodGet, ""},
		{"suppress", func(h *APIHandlers) http.HandlerFunc { return h.RouteWAFSuppress }, http.MethodPost, `{"rule_id":942100}`},
		{"unsuppress", func(h *APIHandlers) http.HandlerFunc { return h.RouteWAFUnsuppress }, http.MethodDelete, ""},
	} {
		if rec := apiCall(db, c.fn, c.method, c.body, "7", "942100", scoped); rec.Code != http.StatusForbidden {
			t.Errorf("%s out of scope: %d, want 403", c.name, rec.Code)
		}
		if rec := apiCall(db, c.fn, c.method, c.body, "999", "942100", super); rec.Code != http.StatusNotFound {
			t.Errorf("%s missing route: %d, want 404", c.name, rec.Code)
		}
		if rec := apiCall(db, c.fn, c.method, c.body, "7", "942100", &middleware.APICaller{UserID: 1, Role: "client"}); rec.Code != http.StatusForbidden {
			t.Errorf("%s client: %d, want 403", c.name, rec.Code)
		}
	}
	sup := func(h *APIHandlers) http.HandlerFunc { return h.RouteWAFSuppress }
	if rec := apiCall(db, sup, http.MethodPost, `{"rule_id":"abc"}`, "7", "", super); rec.Code != http.StatusBadRequest {
		t.Errorf("bad rule_id: %d, want 400", rec.Code)
	}
	if rec := apiCall(db, sup, http.MethodPost, `{"rule_id":942100,"reason":"fp"}`, "7", "", super); rec.Code != http.StatusCreated {
		t.Fatalf("suppress: %d %s", rec.Code, rec.Body.String())
	}
	var rid sql.NullInt64
	if err := db.QueryRow("SELECT route_id FROM waf_rule_suppressions WHERE rule_id='942100'").Scan(&rid); err != nil || !rid.Valid || rid.Int64 != 7 {
		t.Fatalf("suppression not route-scoped: %v %v", rid, err)
	}
	list := func(h *APIHandlers) http.HandlerFunc { return h.RouteWAFSuppressionsList }
	if rec := apiCall(db, list, http.MethodGet, "", "7", "", super); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "942100") {
		t.Errorf("list: %d %s", rec.Code, rec.Body.String())
	}
	del := func(h *APIHandlers) http.HandlerFunc { return h.RouteWAFUnsuppress }
	if rec := apiCall(db, del, http.MethodDelete, "", "7", "942100", super); rec.Code != http.StatusOK {
		t.Errorf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if rec := apiCall(db, del, http.MethodDelete, "", "7", "942100", super); rec.Code != http.StatusNotFound {
		t.Errorf("second delete: %d, want 404", rec.Code)
	}
}

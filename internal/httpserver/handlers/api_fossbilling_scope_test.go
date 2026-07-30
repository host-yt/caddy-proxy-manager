package handlers

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/adminscope"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"

	_ "modernc.org/sqlite"
)

// fbScopeDB: admin 2 is restricted and assigned client 10; service 5 belongs to
// client 10, service 6 to a different tenant (client 99).
func fbScopeDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	for _, s := range []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY, reseller_id INTEGER, is_restricted INTEGER DEFAULT 0, role TEXT DEFAULT 'admin')`,
		`CREATE TABLE admin_client_scope (admin_user_id INTEGER, client_id INTEGER)`,
		`CREATE TABLE clients (id INTEGER PRIMARY KEY, reseller_id INTEGER)`,
		`CREATE TABLE services (id INTEGER PRIMARY KEY, client_id INTEGER)`,
		`CREATE TABLE routes (id INTEGER PRIMARY KEY, service_id INTEGER)`,
		`INSERT INTO users (id, reseller_id, is_restricted) VALUES (1, NULL, 0), (2, NULL, 1)`,
		`INSERT INTO admin_client_scope (admin_user_id, client_id) VALUES (2, 10)`,
		`INSERT INTO clients (id, reseller_id) VALUES (10, NULL), (99, NULL)`,
		`INSERT INTO services (id, client_id) VALUES (5, 10), (6, 99)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
	return db
}

// withChi attaches a chi route context so chi.URLParam works off-router.
func withChi(ctx context.Context, rctx *chi.Context) context.Context {
	return context.WithValue(ctx, chi.RouteCtxKey, rctx)
}

func stringReader(s string) io.Reader { return strings.NewReader(s) }

// TestFOSSBillingDeleteServiceScope: a restricted key may not delete another
// tenant's service, but may still delete its own.
func TestFOSSBillingDeleteServiceScope(t *testing.T) {
	db := fbScopeDB(t)
	h := &FOSSBillingHandlers{
		DB:         func() *sql.DB { return db },
		AdminScope: adminscope.New(func() *sql.DB { return db }),
	}

	cases := []struct {
		name       string
		svcID      string
		caller     *middleware.APICaller
		wantStatus int
	}{
		{"restricted key foreign service denied", "6", &middleware.APICaller{UserID: 2, Role: "admin", Scopes: []string{"admin:write"}}, http.StatusForbidden},
		{"restricted key own service allowed", "5", &middleware.APICaller{UserID: 2, Role: "admin", Scopes: []string{"admin:write"}}, http.StatusOK},
		{"unrestricted key any service allowed", "6", &middleware.APICaller{UserID: 1, Role: "admin"}, http.StatusOK},
		{"missing service denied for restricted key", "1234", &middleware.APICaller{UserID: 2, Role: "admin"}, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodDelete, "/api/v1/provisioning/service/"+tc.svcID, nil)
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", tc.svcID)
			ctx := middleware.ContextWithAPICaller(req.Context(), tc.caller)
			req = req.WithContext(withChi(ctx, rctx))
			rw := httptest.NewRecorder()
			h.DeleteService(rw, req)
			if rw.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rw.Code, tc.wantStatus, rw.Body.String())
			}
		})
	}
}

// TestFOSSBillingSuspendAndProvisionScope covers the other three entry points.
func TestFOSSBillingSuspendAndProvisionScope(t *testing.T) {
	db := fbScopeDB(t)
	h := &FOSSBillingHandlers{
		DB:         func() *sql.DB { return db },
		AdminScope: adminscope.New(func() *sql.DB { return db }),
	}
	restricted := &middleware.APICaller{UserID: 2, Role: "admin", Scopes: []string{"admin:write"}}

	// Suspend of a foreign service.
	req := httptest.NewRequest(http.MethodPut, "/api/v1/provisioning/service/6/suspend", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "6")
	req = req.WithContext(withChi(middleware.ContextWithAPICaller(req.Context(), restricted), rctx))
	rw := httptest.NewRecorder()
	h.SuspendService(rw, req)
	if rw.Code != http.StatusForbidden {
		t.Fatalf("suspend foreign: status = %d, want 403", rw.Code)
	}

	// ProvisionService for a foreign client.
	body := `{"client_id":99,"name":"x","backend_ip":"203.0.113.5","plan_id":1,"port_start":1,"port_end":2}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/provisioning/service", stringReader(body))
	req = req.WithContext(middleware.ContextWithAPICaller(req.Context(), restricted))
	rw = httptest.NewRecorder()
	h.ProvisionService(rw, req)
	if rw.Code != http.StatusForbidden {
		t.Fatalf("provision foreign client: status = %d, want 403 (body %s)", rw.Code, rw.Body.String())
	}

	// ProvisionClient creates a tenant - restricted keys must never reach it.
	req = httptest.NewRequest(http.MethodPost, "/api/v1/provisioning/client", stringReader(`{"email":"a@b.c","name":"n"}`))
	req = req.WithContext(middleware.ContextWithAPICaller(req.Context(), restricted))
	rw = httptest.NewRecorder()
	h.ProvisionClient(rw, req)
	if rw.Code != http.StatusForbidden {
		t.Fatalf("provision client: status = %d, want 403 (body %s)", rw.Code, rw.Body.String())
	}
}

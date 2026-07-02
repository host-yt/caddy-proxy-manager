package handlers

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/host-yt/caddy-proxy-manager/internal/adminscope"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	_ "modernc.org/sqlite"
)

// openResellerAPIDB adds plans/services/routes on top of the scope schema so the
// service-delete and plan-access guards can be exercised end-to-end.
//
// user 1 = reseller-admin (reseller 7); clients 100/101 owned by reseller 7,
// client 200 by reseller 9. plan 1 = global, plan 7 = reseller 7, plan 9 =
// reseller 9. service 10 -> client 100 (own), service 20 -> client 200 (foreign).
func openResellerAPIDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	for _, s := range []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY, reseller_id INTEGER)`,
		`CREATE TABLE clients (id INTEGER PRIMARY KEY, user_id INTEGER, display_name TEXT, reseller_id INTEGER)`,
		`CREATE TABLE admin_client_scope (admin_user_id INTEGER, client_id INTEGER)`,
		`CREATE TABLE plans (id INTEGER PRIMARY KEY, reseller_id INTEGER)`,
		`CREATE TABLE services (id INTEGER PRIMARY KEY, client_id INTEGER)`,
		`CREATE TABLE routes (id INTEGER PRIMARY KEY, service_id INTEGER)`,
		`INSERT INTO users (id, reseller_id) VALUES (1, 7)`,
		`INSERT INTO clients (id, user_id, reseller_id) VALUES (100, 50, 7), (101, 51, 7), (200, 60, 9)`,
		`INSERT INTO plans (id, reseller_id) VALUES (1, NULL), (7, 7), (9, 9)`,
		`INSERT INTO services (id, client_id) VALUES (10, 100), (20, 200)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
	return db
}

func newResellerAPIHandlers(db *sql.DB) *APIHandlers {
	return &APIHandlers{
		DB:         func() *sql.DB { return db },
		AdminScope: adminscope.New(func() *sql.DB { return db }),
		Logger:     slog.Default(),
	}
}

// TestServiceDeleteRejectsForeignTenant is the Codex-flagged regression: a
// reseller-admin key must not delete a service belonging to another tenant.
func TestServiceDeleteRejectsForeignTenant(t *testing.T) {
	db := openResellerAPIDB(t)
	h := newResellerAPIHandlers(db)
	caller := &middleware.APICaller{UserID: 1, Role: "admin"} // reseller 7

	del := func(id string) int {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/services/"+id, nil)
		req = req.WithContext(middleware.ContextWithAPICaller(req.Context(), caller))
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", id)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rr := httptest.NewRecorder()
		h.ServiceDelete(rr, req)
		return rr.Code
	}

	if code := del("20"); code != http.StatusForbidden {
		t.Fatalf("foreign service delete must be 403, got %d", code)
	}
	// The foreign service must still exist.
	var n int
	db.QueryRow("SELECT COUNT(*) FROM services WHERE id=20").Scan(&n)
	if n != 1 {
		t.Fatalf("foreign service was deleted (count=%d)", n)
	}
	// Own service deletes fine.
	if code := del("10"); code != http.StatusOK {
		t.Fatalf("own service delete must be 200, got %d", code)
	}
}

// TestAPIPlanAccessible covers the service-create plan-scope guard.
func TestAPIPlanAccessible(t *testing.T) {
	db := openResellerAPIDB(t)
	h := newResellerAPIHandlers(db)
	ctx := context.Background()
	reseller := &middleware.APICaller{UserID: 1, Role: "admin"} // reseller 7

	if !h.apiPlanAccessible(ctx, reseller, 1) {
		t.Error("global plan 1 must be accessible")
	}
	if !h.apiPlanAccessible(ctx, reseller, 7) {
		t.Error("own reseller plan 7 must be accessible")
	}
	if h.apiPlanAccessible(ctx, reseller, 9) {
		t.Error("foreign reseller plan 9 must be denied")
	}
	// Unrestricted admin (super_admin) may use any plan.
	super := &middleware.APICaller{UserID: 1, Role: "super_admin"}
	if !h.apiPlanAccessible(ctx, super, 9) {
		t.Error("super_admin must reach any plan")
	}
}

// TestEnsureAdminClientStampsReseller covers finding 3: a reseller-admin's
// self-client must carry reseller_id so self-provisioned hosts stay in scope.
func TestEnsureAdminClientStampsReseller(t *testing.T) {
	db := openResellerAPIDB(t)
	ctx := context.Background()

	// New self-client for a fresh reseller-admin user (id 70, reseller 7).
	id, err := ensureAdminClient(ctx, db, 70, 7)
	if err != nil {
		t.Fatalf("ensureAdminClient: %v", err)
	}
	var rid sql.NullInt64
	db.QueryRow("SELECT reseller_id FROM clients WHERE id=?", id).Scan(&rid)
	if !rid.Valid || rid.Int64 != 7 {
		t.Fatalf("new self-client reseller_id = %v, want 7", rid)
	}

	// A pre-existing platform-direct self-client is repaired to the reseller.
	res, _ := db.Exec("INSERT INTO clients (user_id, display_name, reseller_id) VALUES (71, 'x', NULL)")
	existing, _ := res.LastInsertId()
	got, err := ensureAdminClient(ctx, db, 71, 7)
	if err != nil || got != existing {
		t.Fatalf("ensureAdminClient existing: id=%d err=%v", got, err)
	}
	db.QueryRow("SELECT reseller_id FROM clients WHERE id=?", existing).Scan(&rid)
	if !rid.Valid || rid.Int64 != 7 {
		t.Fatalf("existing self-client not repaired, reseller_id = %v", rid)
	}
}

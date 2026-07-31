package handlers

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/adminscope"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/routes"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	_ "modernc.org/sqlite"
)

// openLimitedAdminDB builds the rows the scope/plan guards read: a restricted
// (client-scoped) admin, a reseller-admin and a bare platform admin.
func openLimitedAdminDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	for _, s := range []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT, password_set INTEGER DEFAULT 0,
		   role TEXT DEFAULT 'admin', full_name TEXT, is_active INTEGER DEFAULT 1,
		   reseller_id INTEGER, is_restricted INTEGER DEFAULT 0, auth_epoch INTEGER DEFAULT 0)`,
		`CREATE TABLE admin_client_scope (admin_user_id INTEGER, client_id INTEGER)`,
		`CREATE TABLE clients (id INTEGER PRIMARY KEY, user_id INTEGER, display_name TEXT, external_ref TEXT,
		   tag TEXT, category TEXT, custom_fields TEXT, reseller_id INTEGER)`,
		`CREATE TABLE plans (id INTEGER PRIMARY KEY, name TEXT, reseller_id INTEGER)`,
		`CREATE TABLE resellers (id INTEGER PRIMARY KEY, status TEXT)`,
		`INSERT INTO resellers (id, status) VALUES (7, 'active'), (9, 'active')`,
		// 1: restricted admin assigned to client 70 (owned by reseller 7).
		`INSERT INTO users (id, email, role, is_restricted) VALUES (1, 'r@x', 'admin', 1)`,
		`INSERT INTO admin_client_scope (admin_user_id, client_id) VALUES (1, 70)`,
		// 2: reseller-admin of reseller 7. 3: bare platform admin.
		`INSERT INTO users (id, email, role, reseller_id, is_restricted) VALUES (2, 'a@x', 'admin', 7, 1)`,
		`INSERT INTO users (id, email, role) VALUES (3, 'p@x', 'admin')`,
		`INSERT INTO clients (id, user_id, reseller_id) VALUES (70, 700, 7), (90, 900, 9)`,
		`INSERT INTO plans (id, name, reseller_id) VALUES (1, 'global', NULL), (7, 'own', 7), (9, 'foreign', 9)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
	return db
}

func limitedAdminHandlers(db *sql.DB) *AdminHandlers {
	return &AdminHandlers{
		DB:         func() *sql.DB { return db },
		AdminScope: adminscope.New(func() *sql.DB { return db }),
		Logger:     slog.Default(),
	}
}

var (
	restrictedSess = &auth.Session{UserID: 1, Role: "admin", Restricted: true}
	resellerSess   = &auth.Session{UserID: 2, Role: "admin", ResellerID: 7, Restricted: true}
	platformSess   = &auth.Session{UserID: 3, Role: "admin"}
)

// FINDING 1: a client-scoped admin must never reach the self-provisioning path
// that creates globally-owned (ownerScope=0 / reseller_id NULL) objects.
func TestSelfProvisionScopeDeniesRestrictedAdmin(t *testing.T) {
	h := limitedAdminHandlers(openLimitedAdminDB(t))
	ctx := context.Background()

	if _, ok := h.selfProvisionScope(ctx, restrictedSess); ok {
		t.Error("restricted admin must NOT self-provision")
	}
	if tenant, ok := h.selfProvisionScope(ctx, resellerSess); !ok || !tenant {
		t.Errorf("reseller-admin must self-provision tenant-scoped, got (%v,%v)", tenant, ok)
	}
	if tenant, ok := h.selfProvisionScope(ctx, platformSess); !ok || tenant {
		t.Errorf("platform admin must take the trusted path, got (%v,%v)", tenant, ok)
	}
	if _, ok := h.selfProvisionScope(ctx, nil); ok {
		t.Error("no session must not self-provision")
	}
}

// FINDING 1: the client create surface is reachable through the boundary
// allow-list, so the handler itself must refuse a client-scoped admin.
func TestClientsCreateDeniedForRestrictedAdmin(t *testing.T) {
	db := openLimitedAdminDB(t)
	h := limitedAdminHandlers(db)

	body := "display_name=x&email=new@x&password=passwordpassword"
	r := httptest.NewRequest("POST", "/admin/clients", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(middleware.ContextWithSession(r.Context(), restrictedSess))
	w := httptest.NewRecorder()
	h.ClientsCreate(w, r)

	if loc := w.Header().Get("Location"); !strings.Contains(loc, "forbidden") {
		t.Errorf("want forbidden redirect, got %q", loc)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE email='new@x'`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Error("restricted admin created a platform-direct client account")
	}
}

// FINDING 1: the L4 stream create binds a port on a shared node - a
// client-scoped admin must be refused before anything is provisioned.
func TestStreamsCreateDeniedForRestrictedAdmin(t *testing.T) {
	db := openLimitedAdminDB(t)
	h := limitedAdminHandlers(db)
	h.Routes = &routes.Service{Layer4ModuleAvailable: true}

	body := "protocol=tcp&listen_port=9001&upstream_port=9001&backend_ip=10.1.2.3&node_id=1"
	r := httptest.NewRequest("POST", "/admin/streams", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(middleware.ContextWithSession(r.Context(), restrictedSess))
	w := httptest.NewRecorder()
	h.StreamsCreate(w, r)

	if loc := w.Header().Get("Location"); !strings.Contains(loc, "forbidden") {
		t.Errorf("want forbidden redirect, got %q", loc)
	}
}

// FINDING 2: owning the client is not owning the plan - a client-scoped admin
// may only attach global plans or plans of the tenant's own reseller.
func TestAuthorizePlanForClientRestrictedAdmin(t *testing.T) {
	h := limitedAdminHandlers(openLimitedAdminDB(t))
	ctx := context.Background()

	if h.authorizePlanForClient(ctx, restrictedSess, 70, 9) {
		t.Error("restricted admin must NOT attach a foreign reseller plan")
	}
	if !h.authorizePlanForClient(ctx, restrictedSess, 70, 1) {
		t.Error("global plan must stay attachable")
	}
	if !h.authorizePlanForClient(ctx, restrictedSess, 70, 7) {
		t.Error("plan of the tenant's own reseller must be attachable")
	}
	// Missing plan / no session fail closed.
	if h.authorizePlanForClient(ctx, restrictedSess, 70, 4242) {
		t.Error("unknown plan must be denied")
	}
	if h.authorizePlanForClient(ctx, nil, 70, 1) {
		t.Error("no session must be denied")
	}
	// Platform admin keeps full reach.
	for _, p := range []int64{1, 7, 9} {
		if !h.authorizePlanForClient(ctx, platformSess, 70, p) {
			t.Errorf("platform admin must attach plan %d", p)
		}
	}
}

// FINDING 3: promotion to super_admin must drop the confinement, otherwise the
// account relogs in restricted and cannot be repaired from the scope editor.
func TestUsersUpdatePromotionClearsConfinement(t *testing.T) {
	db := openLimitedAdminDB(t)
	h := limitedAdminHandlers(db)

	body := "full_name=Root&email=r@x&role=super_admin&is_active=1"
	r := httptest.NewRequest("POST", "/admin/users/1/edit", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(middleware.ContextWithSession(r.Context(),
		&auth.Session{UserID: 3, Role: "super_admin"}))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "1")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.UsersUpdate(w, r)

	var role string
	var restricted int
	var rid sql.NullInt64
	var epoch int64
	if err := db.QueryRow(
		`SELECT role, COALESCE(is_restricted,0), reseller_id, auth_epoch FROM users WHERE id=1`,
	).Scan(&role, &restricted, &rid, &epoch); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if role != "super_admin" {
		t.Fatalf("role = %q, want super_admin (loc=%s)", role, w.Header().Get("Location"))
	}
	if restricted != 0 || rid.Valid {
		t.Errorf("promoted super_admin still confined: is_restricted=%d reseller=%v", restricted, rid)
	}
	var scopeRows int
	_ = db.QueryRow(`SELECT COUNT(*) FROM admin_client_scope WHERE admin_user_id=1`).Scan(&scopeRows)
	if scopeRows != 0 {
		t.Error("obsolete admin_client_scope rows survived the promotion")
	}
	if epoch == 0 {
		t.Error("auth epoch not bumped: old confined sessions stay valid")
	}
}

// A confined super_admin row (legacy data) must still resolve as unrestricted.
func TestScopeFilterSuperAdminNeverConfined(t *testing.T) {
	db := openLimitedAdminDB(t)
	if _, err := db.Exec(`UPDATE users SET role='super_admin' WHERE id=1`); err != nil {
		t.Fatalf("update: %v", err)
	}
	_, all, err := adminscope.New(func() *sql.DB { return db }).ScopeFilter(context.Background(), 1)
	if err != nil {
		t.Fatalf("scope filter: %v", err)
	}
	if !all {
		t.Error("super_admin must resolve to unrestricted scope")
	}
}

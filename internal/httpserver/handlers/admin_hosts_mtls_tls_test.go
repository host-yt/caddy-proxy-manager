package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	proxygateway "github.com/host-yt/caddy-proxy-manager"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/routes"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
	"github.com/host-yt/caddy-proxy-manager/internal/view"
)

// mtlsTLSEditDB brings up the real migrated schema (same path a
// db_driver=sqlite install takes) and seeds one TLS-enabled route with mTLS
// off, so HostsUpdate runs its actual queries instead of a hand-trimmed stub.
func mtlsTLSEditDB(t *testing.T) *sql.DB {
	t.Helper()
	prev := store.Driver()
	store.SetDriver("sqlite3")
	t.Cleanup(func() { store.SetDriver(prev) })

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	// Opened through the hook driver (a transparent pass-through unless a test
	// installs a hook) so statement-level interleavings can be made exact.
	// Same pool shape store.Open gives SQLite: one connection.
	db, err := sql.Open(registerMTLSHookDriver(t), filepath.Join(t.TempDir(), "hpg.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if err := store.RunMigrations(ctx, db, proxygateway.MigrationsFS, "migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	for _, s := range []string{
		`INSERT INTO users (id, email, password_hash, role) VALUES (1, 'a@b.c', 'x', 'client')`,
		`INSERT INTO clients (id, user_id, display_name) VALUES (1, 1, 'acme')`,
		`INSERT INTO node_groups (id, name, mode) VALUES (1, 'default', 'single')`,
		`INSERT INTO plans (id, name, node_group_id, max_domains, ssl_enabled, websocket_enabled)
		   VALUES (1, 'basic', 1, 0, 1, 1)`,
		`INSERT INTO services (id, client_id, name, backend_ip, allowed_port_start, allowed_port_end, plan_id, node_group_id)
		   VALUES (1, 1, 'svc', '10.9.9.9', 10000, 20000, 1, 1)`,
		`INSERT INTO caddy_nodes (id, name, api_url, public_hostname, node_group_id, max_routes, current_routes,
		   is_enabled, health_status, approved_at)
		   VALUES (1, 'edge1', 'http://127.0.0.1:1', 'edge1.example', 1, 10, 1, 1, 'healthy', CURRENT_TIMESTAMP)`,
		`INSERT INTO mtls_cas (id, name, common_name, cert_pem, key_pem_enc, not_before, not_after, status)
		   VALUES (1, 'anchor', 'edit-test-ca', '-----BEGIN CERTIFICATE-----x-----END CERTIFICATE-----', '',
		           '2020-01-01 00:00:00', '2090-01-01 00:00:00', 'active')`,
		`INSERT INTO routes (id, service_id, caddy_node_id, domain, upstream_port, upstream_scheme, kind,
		   ssl_enabled, status, domain_verified, require_client_cert)
		   VALUES (7, 1, 1, 'locked.example', 10001, 'http', 'proxy', 1, 'active', 1, 0)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("seed %q: %v", s, err)
		}
	}
	return db
}

// postHostEdit drives POST /admin/hosts/7/edit and returns the Location header.
func postHostEdit(t *testing.T, db *sql.DB, form url.Values) string {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// A cancelled background context keeps the post-commit Caddy push from
	// dialling the fake node after the test.
	bg, cancel := context.WithCancel(context.Background())
	cancel()
	h := &AdminHandlers{
		DB:     func() *sql.DB { return db },
		Logger: logger,
		Routes: &routes.Service{DB: db, Logger: logger, BgCtx: bg},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/hosts/7/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "7")
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = middleware.ContextWithSession(ctx, &auth.Session{UserID: 1, Role: "super_admin"})
	rec := httptest.NewRecorder()
	h.HostsUpdate(rec, req.WithContext(ctx))
	return rec.Header().Get("Location")
}

// baseEditForm is the minimum HostsUpdate accepts for the seeded route.
func baseEditForm() url.Values {
	return url.Values{
		"domain":     {"locked.example"},
		"backend_ip": {"10.9.9.9"},
		"port":       {"10001"},
		"kind":       {"proxy"},
	}
}

// TestHostsUpdate_RejectsMTLSWithoutSSL is the create-path gap arrived at from
// the other side: turning SSL off on a host that requires client certificates
// leaves the same broken state - the panel says "locked", Caddy emits no
// client-auth policy and the host either serves everyone or 503s.
func TestHostsUpdate_RejectsMTLSWithoutSSL(t *testing.T) {
	db := mtlsTLSEditDB(t)

	form := baseEditForm()
	form.Set("require_client_cert", "1")
	form.Set("mtls_ca_id", "1")
	// "ssl" omitted = the operator unticked SSL.
	loc := postHostEdit(t, db, form)
	if !strings.Contains(loc, "err=") || !strings.Contains(loc, "require+SSL") {
		t.Errorf("Location = %q, want an SSL-required error", loc)
	}

	var ssl, flag int
	if err := db.QueryRow("SELECT ssl_enabled, require_client_cert FROM routes WHERE id = 7").Scan(&ssl, &flag); err != nil {
		t.Fatal(err)
	}
	if ssl != 1 || flag != 0 {
		t.Errorf("route was written despite the rejection: ssl=%d require_client_cert=%d", ssl, flag)
	}
}

// The guard must not fire on a legitimate save - it sits after the external
// branch precisely because that branch is the last writer of `ssl`.
func TestHostsUpdate_AllowsMTLSWithSSL(t *testing.T) {
	db := mtlsTLSEditDB(t)

	form := baseEditForm()
	form.Set("ssl", "1")
	form.Set("require_client_cert", "1")
	form.Set("mtls_ca_id", "1")
	if loc := postHostEdit(t, db, form); strings.Contains(loc, "err=") {
		t.Fatalf("legitimate save rejected: %q", loc)
	}

	var ssl, flag int
	if err := db.QueryRow("SELECT ssl_enabled, require_client_cert FROM routes WHERE id = 7").Scan(&ssl, &flag); err != nil {
		t.Fatal(err)
	}
	if ssl != 1 || flag != 1 {
		t.Errorf("want ssl=1 require_client_cert=1, got ssl=%d flag=%d", ssl, flag)
	}
}

// Dropping enforcement together with SSL is the supported way out of the
// broken state, so it must still save.
func TestHostsUpdate_AllowsSSLOffWhenMTLSOff(t *testing.T) {
	db := mtlsTLSEditDB(t)

	if loc := postHostEdit(t, db, baseEditForm()); strings.Contains(loc, "err=") {
		t.Fatalf("turning both off was rejected: %q", loc)
	}
	var ssl, flag int
	if err := db.QueryRow("SELECT ssl_enabled, require_client_cert FROM routes WHERE id = 7").Scan(&ssl, &flag); err != nil {
		t.Fatal(err)
	}
	if ssl != 0 || flag != 0 {
		t.Errorf("want ssl=0 require_client_cert=0, got ssl=%d flag=%d", ssl, flag)
	}
}

// The edit page must not claim "mTLS enforced" for a host whose SSL is off -
// that pill is exactly what made the broken state look healthy.
func TestHostEditMTLSWarnsWhenSSLOff(t *testing.T) {
	tpls, err := view.LoadAdminTemplates()
	if err != nil {
		t.Fatalf("load admin templates: %v", err)
	}
	render := func(ssl bool) string {
		t.Helper()
		d := hostEditData{
			baseAdminData:     baseAdminData{Role: "admin", CSRF: "csrf", CSPNonce: "nonce"},
			RouteID:           1,
			Domain:            "locked.example",
			SSL:               ssl,
			RequireClientCert: true,
			MTLSCAID:          1,
			MTLSCAActive:      true,
			MTLSCAs:           []mtlsCAOption{{ID: 1, Label: "corp-ca"}},
		}
		var buf bytes.Buffer
		if err := tpls.Render(&buf, "hosts_edit", fillBreadcrumbs("hosts_edit", d)); err != nil {
			t.Fatalf("render hosts_edit: %v", err)
		}
		return buf.String()
	}

	off := render(false)
	if !strings.Contains(off, "SSL off, not enforced") {
		t.Error("mTLS pill does not flag that SSL is off")
	}
	if !strings.Contains(off, "no client certificate is ever checked") {
		t.Error("edit page does not explain the SSL dependency")
	}

	if on := render(true); !strings.Contains(on, "mTLS enforced") || strings.Contains(on, "SSL off, not enforced") {
		t.Error("a TLS-enabled host must still read as enforced")
	}
}

// Same invariant on the REST API: PATCH /routes/{id} could clear ssl_enabled
// on a host that requires client certificates, reaching the broken state
// without ever opening the edit page.
func TestAPIRouteUpdate_RejectsSSLOffWhileMTLSOn(t *testing.T) {
	db := mtlsTLSEditDB(t)
	if _, err := db.Exec("UPDATE routes SET require_client_cert = 1, mtls_ca_id = 1 WHERE id = 7"); err != nil {
		t.Fatal(err)
	}
	patch := func(body string) *httptest.ResponseRecorder { return patchRoute7(t, db, body) }

	if rec := patch(`{"ssl_enabled":false}`); rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	var ssl int
	if err := db.QueryRow("SELECT ssl_enabled FROM routes WHERE id = 7").Scan(&ssl); err != nil {
		t.Fatal(err)
	}
	if ssl != 1 {
		t.Error("ssl_enabled was cleared on an mTLS-enforced route")
	}

	// Unrelated fields must still patch.
	if rec := patch(`{"websocket":true}`); rec.Code != http.StatusOK {
		t.Errorf("unrelated patch rejected: %d %s", rec.Code, rec.Body.String())
	}
}

// patchRoute7 drives PATCH /api/v1/routes/7 as a super_admin API caller.
func patchRoute7(t *testing.T, db *sql.DB, body string) *httptest.ResponseRecorder {
	t.Helper()
	h := &APIHandlers{DB: func() *sql.DB { return db }, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/routes/7", strings.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "7")
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = middleware.ContextWithAPICaller(ctx, &middleware.APICaller{UserID: 1, Role: "super_admin"})
	rec := httptest.NewRecorder()
	h.RouteUpdate(rec, req.WithContext(ctx))
	return rec
}

// The race the guard has to survive: mTLS is switched on after this request
// has already decided that clearing SSL is safe, and before its UPDATE runs.
// The hook fires on the UPDATE itself, so the interleaving is exact rather
// than timing-dependent. A check that lives outside the write loses here.
func TestAPIRouteUpdate_MTLSEnabledBetweenCheckAndWrite(t *testing.T) {
	db := mtlsTLSEditDB(t)
	var once sync.Once
	setMTLSSQLHook(t, func(exec func(string) error, query string) error {
		if strings.HasPrefix(query, "UPDATE routes SET") {
			once.Do(func() {
				if err := exec("UPDATE routes SET require_client_cert = 1, mtls_ca_id = 1 WHERE id = 7"); err != nil {
					t.Errorf("interleaved enable failed: %v", err)
				}
			})
		}
		return nil
	})

	if rec := patchRoute7(t, db, `{"ssl_enabled":false}`); rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	var ssl, flag int
	if err := db.QueryRow("SELECT ssl_enabled, require_client_cert FROM routes WHERE id = 7").Scan(&ssl, &flag); err != nil {
		t.Fatal(err)
	}
	if ssl != 1 || flag != 1 {
		t.Errorf("want ssl=1 require_client_cert=1, got ssl=%d flag=%d", ssl, flag)
	}
}

// A prerequisite read that fails must reject the request. The old guard
// treated a read error as "not enforced" and cleared SSL anyway.
func TestAPIRouteUpdate_RejectsWhenMTLSReadFails(t *testing.T) {
	db := mtlsTLSEditDB(t)
	if _, err := db.Exec("UPDATE routes SET require_client_cert = 1, mtls_ca_id = 1 WHERE id = 7"); err != nil {
		t.Fatal(err)
	}
	setMTLSSQLHook(t, func(_ func(string) error, query string) error {
		if strings.Contains(query, "SELECT COALESCE(require_client_cert") {
			return errors.New("injected read failure")
		}
		return nil
	})

	if rec := patchRoute7(t, db, `{"ssl_enabled":false}`); rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	var ssl int
	if err := db.QueryRow("SELECT ssl_enabled FROM routes WHERE id = 7").Scan(&ssl); err != nil {
		t.Fatal(err)
	}
	if ssl != 1 {
		t.Error("ssl_enabled was cleared even though the mTLS read failed")
	}
}

// ---- statement-level hook driver ---------------------------------------
//
// A thin pass-through wrapper around the SQLite driver that can run something
// (or fail) right before a chosen statement executes. It is the only way to
// pin a read/write interleaving down deterministically; the alternative is a
// goroutine race that passes for the wrong reason.

// mtlsSQLHook runs before each statement. exec runs raw SQL on the same
// connection, bypassing the hook.
type mtlsSQLHook func(exec func(string) error, query string) error

var (
	mtlsHookMu   sync.Mutex
	mtlsHookFn   mtlsSQLHook
	mtlsHookOnce sync.Once
)

func setMTLSSQLHook(t *testing.T, fn mtlsSQLHook) {
	t.Helper()
	mtlsHookMu.Lock()
	mtlsHookFn = fn
	mtlsHookMu.Unlock()
	t.Cleanup(func() {
		mtlsHookMu.Lock()
		mtlsHookFn = nil
		mtlsHookMu.Unlock()
	})
}

const mtlsHookDriverName = "sqlite-mtls-hook"

// registerMTLSHookDriver registers the wrapper over whatever driver store uses
// for SQLite and returns its name.
func registerMTLSHookDriver(t *testing.T) string {
	t.Helper()
	mtlsHookOnce.Do(func() {
		probe, err := sql.Open("sqlite", ":memory:")
		if err != nil {
			t.Fatalf("probe sqlite driver: %v", err)
		}
		inner := probe.Driver()
		_ = probe.Close()
		sql.Register(mtlsHookDriverName, mtlsHookDriver{inner: inner})
	})
	return mtlsHookDriverName
}

type mtlsHookDriver struct{ inner driver.Driver }

func (d mtlsHookDriver) Open(dsn string) (driver.Conn, error) {
	c, err := d.inner.Open(dsn)
	if err != nil {
		return nil, err
	}
	return &mtlsHookConn{Conn: c}, nil
}

// mtlsHookConn deliberately exposes only driver.Conn, so database/sql takes
// the Prepare path and every statement passes through the hook.
type mtlsHookConn struct{ driver.Conn }

func (c *mtlsHookConn) raw(query string) error {
	st, err := c.Conn.Prepare(query)
	if err != nil {
		return err
	}
	defer st.Close()
	if ec, ok := st.(driver.StmtExecContext); ok {
		_, err = ec.ExecContext(context.Background(), nil)
		return err
	}
	_, err = st.Exec(nil)
	return err
}

func (c *mtlsHookConn) Prepare(query string) (driver.Stmt, error) {
	st, err := c.Conn.Prepare(query)
	if err != nil {
		return nil, err
	}
	return &mtlsHookStmt{Stmt: st, conn: c, query: query}, nil
}

type mtlsHookStmt struct {
	driver.Stmt
	conn  *mtlsHookConn
	query string
}

func (s *mtlsHookStmt) fire() error {
	mtlsHookMu.Lock()
	fn := mtlsHookFn
	mtlsHookMu.Unlock()
	if fn == nil {
		return nil
	}
	return fn(s.conn.raw, s.query)
}

func (s *mtlsHookStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	if err := s.fire(); err != nil {
		return nil, err
	}
	ec, ok := s.Stmt.(driver.StmtExecContext)
	if !ok {
		return nil, errors.New("wrapped stmt has no ExecContext")
	}
	return ec.ExecContext(ctx, args)
}

func (s *mtlsHookStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	if err := s.fire(); err != nil {
		return nil, err
	}
	qc, ok := s.Stmt.(driver.StmtQueryContext)
	if !ok {
		return nil, errors.New("wrapped stmt has no QueryContext")
	}
	return qc.QueryContext(ctx, args)
}

// Keep the driver's own argument conversion; ErrSkip falls back to the
// database/sql default when it has none.
func (s *mtlsHookStmt) CheckNamedValue(nv *driver.NamedValue) error {
	if c, ok := s.Stmt.(driver.NamedValueChecker); ok {
		return c.CheckNamedValue(nv)
	}
	return driver.ErrSkip
}

package handlers

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/host-yt/caddy-proxy-manager/internal/domain/portal"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
	"github.com/host-yt/caddy-proxy-manager/internal/store/sqlitetest"
)

// portalVerifyDB seeds one host serving a public catch-all plus a protected
// /team-a route - the shape HPG-002 mis-resolved.
func portalVerifyDB(t *testing.T) *sql.DB {
	t.Helper()
	prev := store.Driver()
	store.SetDriver("sqlite3")
	t.Cleanup(func() { store.SetDriver(prev) })
	db, err := sql.Open("sqlite", sqlitetest.MigratedCopy(t, "verify.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, s := range []string{
		`INSERT INTO node_groups (id, name) VALUES (1, 'g1')`,
		`INSERT INTO caddy_nodes (id, name, api_url, is_enabled, node_group_id) VALUES (1, 'edge1', 'http://n1:2019', 1, 1)`,
		`INSERT INTO plans (id, name, node_group_id) VALUES (1, 'p1', 1)`,
		`INSERT INTO services (id, client_id, name, backend_ip, allowed_port_start, allowed_port_end, plan_id, node_group_id)
		   VALUES (1, 1, 'svc', '10.0.0.9', 1, 65535, 1, 1)`,
		`INSERT INTO routes (id, service_id, caddy_node_id, domain, path_prefix, upstream_port, upstream_scheme,
		   ssl_enabled, status, kind, domain_verified, portal_protect)
		   VALUES (10, 1, 1, 'app.example', '', 8080, 'http', 1, 'active', 'proxy', 1, 0)`,
		`INSERT INTO routes (id, service_id, caddy_node_id, domain, path_prefix, upstream_port, upstream_scheme,
		   ssl_enabled, status, kind, domain_verified, portal_protect)
		   VALUES (11, 1, 1, 'app.example', '/team-a', 8080, 'http', 1, 'active', 'proxy', 1, 1)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("seed %q: %v", s, err)
		}
	}
	return db
}

func verifyRequest(uri string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://app.example/hpg-portal/verify", nil)
	r.Header.Set("X-Forwarded-Host", "app.example")
	if uri != "" {
		r.Header.Set("X-Forwarded-Uri", uri)
	}
	return r
}

// HPG-002 regression: a protected path on a host that also serves a public
// route used to be answered by whichever record the host lookup returned
// first, so an anonymous request could get a 200. The decision must follow the
// path to the exact route.
func TestVerifyBindsDecisionToExactRoute(t *testing.T) {
	db := portalVerifyDB(t)
	h := &PortalHandlers{DB: func() *sql.DB { return db }, Portal: portal.New(func() *sql.DB { return db })}

	rec := httptest.NewRecorder()
	h.Verify(rec, verifyRequest("/team-a/secret?x=1"))
	if rec.Code != http.StatusFound {
		t.Errorf("anonymous request to the protected path: status = %d, want 302", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.Verify(rec, verifyRequest("/public/page"))
	if rec.Code != http.StatusOK {
		t.Errorf("public sibling path: status = %d, want 200", rec.Code)
	}
}

// The resource identity comes from the gate config the panel emits. Without
// it - a direct hit on the verify endpoint, or a node running a config that
// never set the header - there is nothing to authorize against: deny.
func TestVerifyDeniesWithoutTrustedURI(t *testing.T) {
	db := portalVerifyDB(t)
	h := &PortalHandlers{DB: func() *sql.DB { return db }, Portal: portal.New(func() *sql.DB { return db })}

	for _, uri := range []string{"", "not-a-path", "https://evil.example/team-a"} {
		rec := httptest.NewRecorder()
		h.Verify(rec, verifyRequest(uri))
		if rec.Code != http.StatusFound {
			t.Errorf("X-Forwarded-Uri %q: status = %d, want 302 (deny)", uri, rec.Code)
		}
	}
}

func TestPortalRequestPath(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"/team-a/docs?x=1", "/team-a/docs", true},
		{"/", "/", true},
		{"", "", false},
		{"team-a", "", false},
		{"https://evil.example/team-a", "", false},
		{"//evil.example/team-a", "", false},
	}
	for _, c := range cases {
		r := verifyRequest("")
		if c.in != "" {
			r.Header.Set("X-Forwarded-Uri", c.in)
		}
		got, ok := portalRequestPath(r)
		if got != c.want || ok != c.ok {
			t.Errorf("portalRequestPath(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

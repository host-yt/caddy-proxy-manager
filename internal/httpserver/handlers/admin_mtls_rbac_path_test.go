package handlers

import (
	"database/sql"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/security"
)

var rbacUserPEM = mustLeafPEM(6, "dev", time.Now().Add(time.Hour))

// rbacFixture adds role "user" (id 2) held by cert 6 on top of the base fixture.
func rbacFixture(t *testing.T, extra ...string) func(uri, certPEM string) int {
	t.Helper()
	db := openRBACTestDB(t)
	insertRBACCert(t, db, 6, "dev", "active", rbacUserPEM)
	for _, s := range append([]string{
		`INSERT INTO mtls_roles (id, name) VALUES (2, 'user')`,
		`INSERT INTO mtls_cert_roles (cert_id, role_id) VALUES (6, 2)`,
	}, extra...) {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("%q: %v", s, err)
		}
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	h := &AdminHandlers{DB: func() *sql.DB { return db }, Logger: slog.Default(), MTLSRBACKey: key}
	return func(uri, certPEM string) int {
		return rbacRequest(t, h, "7", withLeaf(certPEM, map[string]string{
			"X-Forwarded-Uri":            uri,
			security.MTLSRBACHeaderNode:  "1",
			security.MTLSRBACHeaderToken: security.MTLSRBACToken(key, 1, 7),
		}))
	}
}

func TestMTLSRBACCheck_EncodedPathsCannotDodgeRule(t *testing.T) {
	check := rbacFixture(t)
	cases := map[string]int{
		"/public":                  http.StatusOK,
		"/public?x=/admin/":        http.StatusOK,
		"/admin/panel":             http.StatusForbidden,
		"/admin%2Fpanel":           http.StatusForbidden,
		"/admin%252Fpanel":         http.StatusForbidden,
		"/%61dmin/panel":           http.StatusForbidden,
		"/public/../admin/panel":   http.StatusForbidden,
		"/public/%2e%2e/admin/x":   http.StatusForbidden,
		"//admin/panel":            http.StatusForbidden,
		"/admin\\panel":            http.StatusForbidden,
		"/admin%5Cpanel":           http.StatusForbidden,
		"/admin%zz":                http.StatusForbidden,
		"http://h.example/admin/x": http.StatusForbidden,
		"*":                        http.StatusForbidden,
	}
	for uri, want := range cases {
		if got := check(uri, rbacUserPEM); got != want {
			t.Errorf("%q: status = %d, want %d", uri, got, want)
		}
	}
}

func TestMTLSRBACCheck_MostSpecificRuleWins(t *testing.T) {
	broad := `INSERT INTO mtls_path_rules (route_id, path_pattern, required_role_id) VALUES (7, '/app/*', 2)`
	exact := `INSERT INTO mtls_path_rules (route_id, path_pattern, required_role_id) VALUES (7, '/app/secrets', 1)`
	prefix := `INSERT INTO mtls_path_rules (route_id, path_pattern, required_role_id) VALUES (7, '/app/keys/*', 1)`
	for name, order := range map[string][]string{
		"broad-first":    {broad, exact, prefix},
		"specific-first": {exact, prefix, broad},
	} {
		t.Run(name, func(t *testing.T) {
			check := rbacFixture(t, append([]string{`DELETE FROM mtls_path_rules`}, order...)...)
			for _, c := range []struct {
				uri, cert string
				want      int
			}{
				{"/app/secrets", rbacUserPEM, http.StatusForbidden},
				{"/app/keys/1", rbacUserPEM, http.StatusForbidden},
				{"/app/home", rbacUserPEM, http.StatusOK},
				{"/app/secrets", rbacOpsPEM, http.StatusOK},
			} {
				if got := check(c.uri, c.cert); got != c.want {
					t.Errorf("%s: status = %d, want %d", c.uri, got, c.want)
				}
			}
		})
	}
}

func TestMTLSRBACCheck_UnreadableRuleFailsClosed(t *testing.T) {
	// NULL pattern makes Scan fail; the route must not fall back to "no rules".
	check := rbacFixture(t, `INSERT INTO mtls_path_rules (route_id, path_pattern, required_role_id) VALUES (7, NULL, 1)`)
	if got := check("/public", rbacUserPEM); got == http.StatusOK {
		t.Fatalf("status = %d, want non-200 on unreadable rules", got)
	}
}

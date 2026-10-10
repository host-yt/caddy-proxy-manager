package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	_ "modernc.org/sqlite"

	"github.com/host-yt/caddy-proxy-manager/internal/mtls"
	"github.com/host-yt/caddy-proxy-manager/internal/security"
)

// openRBACTestDB builds the tables the RBAC check reads: one route on node 1
// with a /admin/* rule requiring the "admin" role, and one active cert holding
// that role.
func openRBACTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	stmts := []string{
		`CREATE TABLE routes (id INTEGER PRIMARY KEY, caddy_node_id INTEGER, mtls_ca_id INTEGER)`,
		`CREATE TABLE route_node_assignments (route_id INTEGER, node_id INTEGER)`,
		`CREATE TABLE mtls_roles (id INTEGER PRIMARY KEY, name TEXT)`,
		`CREATE TABLE mtls_path_rules (id INTEGER PRIMARY KEY, route_id INTEGER, path_pattern TEXT, required_role_id INTEGER)`,
		`CREATE TABLE mtls_issued_certs (id INTEGER PRIMARY KEY, ca_id INTEGER, subject TEXT, serial TEXT, cert_pem TEXT, status TEXT)`,
		`CREATE TABLE mtls_cert_roles (cert_id INTEGER, role_id INTEGER)`,
		`INSERT INTO routes (id, caddy_node_id, mtls_ca_id) VALUES (7, 1, 3)`,
		`INSERT INTO mtls_roles (id, name) VALUES (1, 'admin')`,
		`INSERT INTO mtls_path_rules (id, route_id, path_pattern, required_role_id) VALUES (1, 7, '/admin/*', 1)`,
		`INSERT INTO mtls_cert_roles (cert_id, role_id) VALUES (5, 1)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("schema %q: %v", s, err)
		}
	}
	insertRBACCert(t, db, 5, "ops", "active", rbacOpsPEM)
	return db
}

// rbacOpsPEM is the fixture leaf (row 5) holding the "admin" role.
var rbacOpsPEM = mustLeafPEM(5, "ops", time.Now().Add(time.Hour))

func insertRBACCert(t *testing.T, db *sql.DB, id int64, subject, status, certPEM string) {
	t.Helper()
	c, err := mtls.ParseCert(certPEM)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO mtls_issued_certs (id, ca_id, subject, serial, cert_pem, status) VALUES (?, 3, ?, ?, ?, ?)`,
		id, subject, c.SerialNumber.String(), certPEM, status); err != nil {
		t.Fatalf("insert cert: %v", err)
	}
}

// mustLeafPEM self-signs a throwaway leaf; RBAC only reads serial, DER and NotAfter.
func mustLeafPEM(serial int64, cn string, notAfter time.Time) string {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notAfter.Add(-48 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// withLeaf adds the identity headers Caddy renders for certPEM.
func withLeaf(certPEM string, h map[string]string) map[string]string {
	c, err := mtls.ParseCert(certPEM)
	if err != nil {
		panic(err)
	}
	h["X-Mtls-Serial"] = c.SerialNumber.String()
	h["X-Mtls-Fingerprint"] = mtls.FingerprintOf(c)
	h["X-Mtls-Subject"] = c.Subject.String()
	return h
}

func rbacRequest(t *testing.T, h *AdminHandlers, routeID string, headers map[string]string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/internal/mtls-rbac/"+routeID, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("route_id", routeID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	h.MTLSRBACCheck(rec, req)
	return rec.Code
}

// TestMTLSRBACCheck_RequiresNodeToken is the MTLS-01 regression: reaching the
// endpoint from inside the mesh is no longer enough - a caller must present the
// (node, route) token the panel wrote into that node's Caddy config.
func TestMTLSRBACCheck_RequiresNodeToken(t *testing.T) {
	db := openRBACTestDB(t)
	key := []byte("0123456789abcdef0123456789abcdef")
	h := &AdminHandlers{DB: func() *sql.DB { return db }, Logger: slog.Default(), MTLSRBACKey: key}

	good := security.MTLSRBACToken(key, 1, 7)
	cases := []struct {
		name    string
		route   string
		headers map[string]string
		want    int
	}{
		{
			name:  "valid token and role",
			route: "7",
			headers: withLeaf(rbacOpsPEM, map[string]string{
				"X-Forwarded-Uri":            "/admin/panel",
				security.MTLSRBACHeaderNode:  "1",
				security.MTLSRBACHeaderToken: good,
				"X-Forwarded-Method":         "GET",
			}),
			want: http.StatusOK,
		},
		{
			name:    "no token at all",
			route:   "7",
			headers: withLeaf(rbacOpsPEM, map[string]string{"X-Forwarded-Uri": "/admin/panel"}),
			want:    http.StatusForbidden,
		},
		{
			name:  "token minted for another route",
			route: "7",
			headers: withLeaf(rbacOpsPEM, map[string]string{
				"X-Forwarded-Uri":            "/admin/panel",
				security.MTLSRBACHeaderNode:  "1",
				security.MTLSRBACHeaderToken: security.MTLSRBACToken(key, 1, 8),
			}),
			want: http.StatusForbidden,
		},
		{
			name:  "token from a node that does not serve the route",
			route: "7",
			headers: withLeaf(rbacOpsPEM, map[string]string{
				"X-Forwarded-Uri":            "/admin/panel",
				security.MTLSRBACHeaderNode:  "2",
				security.MTLSRBACHeaderToken: security.MTLSRBACToken(key, 2, 7),
			}),
			want: http.StatusForbidden,
		},
		{
			name:  "valid token but no identity headers",
			route: "7",
			headers: map[string]string{
				"X-Mtls-Subject":             "CN=ops",
				"X-Forwarded-Uri":            "/admin/panel",
				security.MTLSRBACHeaderNode:  "1",
				security.MTLSRBACHeaderToken: good,
			},
			want: http.StatusForbidden,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := rbacRequest(t, h, c.route, c.headers); got != c.want {
				t.Errorf("status = %d, want %d", got, c.want)
			}
		})
	}
}

// TestMTLSRBACCheck_FanoutPeerAccepted proves an active-active peer that serves
// the route via route_node_assignments can still run checks.
func TestMTLSRBACCheck_FanoutPeerAccepted(t *testing.T) {
	db := openRBACTestDB(t)
	if _, err := db.Exec(`INSERT INTO route_node_assignments (route_id, node_id) VALUES (7, 2)`); err != nil {
		t.Fatalf("assign: %v", err)
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	h := &AdminHandlers{DB: func() *sql.DB { return db }, Logger: slog.Default(), MTLSRBACKey: key}
	code := rbacRequest(t, h, "7", withLeaf(rbacOpsPEM, map[string]string{
		"X-Forwarded-Uri":            "/admin/panel",
		security.MTLSRBACHeaderNode:  "2",
		security.MTLSRBACHeaderToken: security.MTLSRBACToken(key, 2, 7),
	}))
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
}

// TestMTLSRBACCheck_AllowUnsignedEscapeHatch keeps the documented upgrade-window
// behaviour working (and only that).
func TestMTLSRBACCheck_AllowUnsignedEscapeHatch(t *testing.T) {
	db := openRBACTestDB(t)
	h := &AdminHandlers{
		DB: func() *sql.DB { return db }, Logger: slog.Default(),
		MTLSRBACKey: []byte("0123456789abcdef0123456789abcdef"), MTLSRBACAllowUnsigned: true,
	}
	code := rbacRequest(t, h, "7", withLeaf(rbacOpsPEM, map[string]string{
		"X-Forwarded-Uri": "/admin/panel",
	}))
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with MTLS_RBAC_ALLOW_UNSIGNED", code)
	}
}

package handlers

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/routes"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// hostsR14DB is a minimal fixture for bulk actions + legacy alias review.
func hostsR14DB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "r14.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	for _, s := range []string{
		`CREATE TABLE routes (id INTEGER PRIMARY KEY, service_id INTEGER, caddy_node_id INTEGER,
		   domain TEXT, aliases TEXT, aliases_verified TEXT, status TEXT,
		   ssl_enabled INTEGER, domain_verified INTEGER, last_error TEXT, updated_at TEXT)`,
		`CREATE TABLE route_alias_legacy_claims (route_id INTEGER PRIMARY KEY, aliases TEXT,
		   status TEXT DEFAULT 'pending', created_at TEXT DEFAULT '2026-07-31 00:00:00',
		   resolved_at TEXT, resolved_by INTEGER)`,
		`CREATE TABLE services (id INTEGER PRIMARY KEY, client_id INTEGER)`,
		`CREATE TABLE clients (id INTEGER PRIMARY KEY, user_id INTEGER, display_name TEXT)`,
		`CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT)`,
		`CREATE TABLE caddy_nodes (id INTEGER PRIMARY KEY, name TEXT)`,
		`INSERT INTO services (id, client_id) VALUES (1, 1)`,
		`INSERT INTO clients (id, user_id, display_name) VALUES (1, 1, 'Acme')`,
		`INSERT INTO users (id, email) VALUES (1, 'acme@example.com')`,
		`INSERT INTO caddy_nodes (id, name) VALUES (1, 'edge1')`,
		// Route 10: owner proved the primary. Route 11: primary reset to unproven
		// by a tenant-scoped edit (the takeover setup).
		`INSERT INTO routes (id, service_id, caddy_node_id, domain, status, ssl_enabled, domain_verified)
		   VALUES (10, 1, 1, 'owned.example', 'failed', 1, 1)`,
		`INSERT INTO routes (id, service_id, caddy_node_id, domain, status, ssl_enabled, domain_verified)
		   VALUES (11, 1, 1, 'victim.example', 'pending_dns', 1, 0)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
	return db
}

func hostsR14Handlers(db *sql.DB) *AdminHandlers {
	return &AdminHandlers{
		DB:     func() *sql.DB { return db },
		Logger: slog.Default(),
		Routes: &routes.Service{DB: db, Logger: slog.Default()},
	}
}

// FINDING 2 (r14): bulk retry_ssl moved any ssl-enabled route to pending_ssl,
// a serving status the emission query accepts. A scoped admin could repoint a
// route at an unowned hostname, bulk-retry, and serve it.
func TestBulkRetrySSLRequiresVerifiedDomain(t *testing.T) {
	db := hostsR14DB(t)
	h := hostsR14Handlers(db)

	form := url.Values{"action": {"retry_ssl"}, "ids": {"10", "11"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/hosts/bulk", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(middleware.ContextWithSession(req.Context(),
		&auth.Session{UserID: 3, Role: "super_admin"}))
	h.HostsBulk(httptest.NewRecorder(), req)

	var verifiedStatus, unverifiedStatus string
	if err := db.QueryRow("SELECT status FROM routes WHERE id=10").Scan(&verifiedStatus); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT status FROM routes WHERE id=11").Scan(&unverifiedStatus); err != nil {
		t.Fatal(err)
	}
	if verifiedStatus != "pending_ssl" {
		t.Errorf("verified route status = %q, want pending_ssl", verifiedStatus)
	}
	if unverifiedStatus == "pending_ssl" {
		t.Error("unverified route was bulk-retried into a serving status")
	}
}

// FINDING 1 (r14): migration 00138 parks the 00136 backfill instead of trusting
// it. The report must name the aliases that stopped serving, and approving a
// claim must restore only aliases the route still lists.
func TestLegacyAliasReviewAndApprove(t *testing.T) {
	db := hostsR14DB(t)
	h := hostsR14Handlers(db)
	ctx := context.Background()

	if _, err := db.Exec(
		`UPDATE routes SET aliases='legacy.example,fresh.example', aliases_verified=NULL WHERE id=10`); err != nil {
		t.Fatal(err)
	}
	// 00138 recorded only what 00136 had backfilled; fresh.example was added later.
	if _, err := db.Exec(
		`INSERT INTO route_alias_legacy_claims (route_id, aliases) VALUES (10, 'legacy.example,gone.example')`); err != nil {
		t.Fatal(err)
	}

	rows := loadLegacyAliasRows(ctx, db)
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if got := strings.Join(rows[0].Unproven, ","); got != "legacy.example" {
		t.Errorf("not-serving report = %q, want legacy.example", got)
	}

	n, err := h.approveLegacyAliases(ctx, nil, 10)
	if err != nil || n != 1 {
		t.Fatalf("approve = (%d,%v)", n, err)
	}
	var verified, status string
	if err := db.QueryRow("SELECT COALESCE(aliases_verified,'') FROM routes WHERE id=10").Scan(&verified); err != nil {
		t.Fatal(err)
	}
	if verified != "legacy.example" {
		t.Errorf("aliases_verified = %q, want legacy.example (fresh + removed aliases must not be vouched for)", verified)
	}
	if err := db.QueryRow("SELECT status FROM route_alias_legacy_claims WHERE route_id=10").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "approved" {
		t.Errorf("claim status = %q, want approved", status)
	}
}

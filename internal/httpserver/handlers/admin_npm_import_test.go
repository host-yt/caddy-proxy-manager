package handlers

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/routes"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// newNpmTestDB has the two tables a dry run reads: one approved node (so the
// import is possible at all) and the routes table (for duplicate detection).
func newNpmTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	stmts := []string{
		`CREATE TABLE caddy_nodes (id INTEGER PRIMARY KEY, node_group_id INTEGER,
			approved_at TIMESTAMP NULL, is_enabled INTEGER)`,
		`CREATE TABLE routes (id INTEGER PRIMARY KEY, domain TEXT)`,
		`INSERT INTO caddy_nodes VALUES (1, 1, CURRENT_TIMESTAMP, 1)`,
		`INSERT INTO routes VALUES (1, 'taken.example')`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("schema %q: %v", s, err)
		}
	}
	return db
}

func npmDryRun(t *testing.T, db *sql.DB, backup npmBackup) npmImportResult {
	t.Helper()
	h := &AdminHandlers{
		DB:     func() *sql.DB { return db },
		Logger: slog.Default(),
		Routes: &routes.Service{},
	}
	req := httptest.NewRequest("POST", "/admin/tools/npm-import", nil)
	req = req.WithContext(middleware.ContextWithSession(req.Context(), &auth.Session{UserID: 1, Role: "super_admin"}))
	return h.runNpmImport(req, backup, true)
}

func findItem(items []npmImportItem, name, action string) *npmImportItem {
	for i := range items {
		if items[i].Name == name && items[i].Action == action {
			return &items[i]
		}
	}
	return nil
}

// A dry run must report what a real import would do and write nothing.
func TestNpmImport_DryRunReportsWithoutWriting(t *testing.T) {
	db := newNpmTestDB(t)
	backup := npmBackup{
		ProxyHosts: []npmProxyHost{
			{DomainNames: []string{"app.example"}, ForwardScheme: "http", ForwardHost: "10.9.9.9", ForwardPort: 8080, Enabled: 1},
			{DomainNames: []string{"taken.example"}, ForwardHost: "10.9.9.9", ForwardPort: 8080, Enabled: 1},
			{DomainNames: []string{"off.example"}, ForwardHost: "10.9.9.9", ForwardPort: 80, Enabled: 0},
		},
		RedirectionHosts: []npmRedirectHost{
			{DomainNames: []string{"old.example"}, ForwardScheme: "auto", ForwardDomainName: "new.example",
				ForwardHTTPCode: 301, Enabled: 1},
		},
	}
	res := npmDryRun(t, db, backup)

	if !res.DryRun {
		t.Fatal("result not marked as a dry run")
	}
	if len(res.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", res.Errors)
	}
	if it := findItem(res.Items, "app.example", npmActionImported); it == nil {
		t.Errorf("proxy host not planned for import: %+v", res.Items)
	} else if !strings.Contains(it.Detail, "10.9.9.9:8080") {
		t.Errorf("detail does not name the backend: %q", it.Detail)
	}
	if findItem(res.Items, "taken.example", npmActionSkipped) == nil {
		t.Error("already-mapped domain not reported as skipped")
	}
	if findItem(res.Items, "off.example", npmActionSkipped) == nil {
		t.Error("disabled host not reported as skipped")
	}
	if it := findItem(res.Items, "old.example", npmActionImported); it == nil {
		t.Error("redirect not planned for import")
	} else if !strings.Contains(it.Detail, "https://new.example") {
		t.Errorf("redirect target wrong: %q", it.Detail)
	}

	// Nothing may have been written: no client/service/plan rows, no routes.
	var routeCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM routes").Scan(&routeCount); err != nil {
		t.Fatalf("count routes: %v", err)
	}
	if routeCount != 1 {
		t.Errorf("dry run wrote routes: %d rows (want the 1 pre-existing)", routeCount)
	}
}

// Sections the panel cannot reproduce must be reported, not dropped silently.
func TestNpmImport_ReportsUnsupportedSections(t *testing.T) {
	db := newNpmTestDB(t)
	backup := npmBackup{
		Streams: []npmStream{
			{IncomingPort: 5432, ForwardingHost: "10.1.1.1", ForwardingPort: 5432, TCPForwarding: true, Enabled: 1},
			{IncomingPort: 9999, ForwardingHost: "10.1.1.2", ForwardingPort: 9999, Enabled: 0}, // disabled: no line
		},
		AccessLists:  []npmAccessList{{Name: "staff"}},
		Certificates: []npmCertificate{{Provider: "other", NiceName: "wildcard"}, {Provider: "letsencrypt", NiceName: "le"}},
		DeadHosts:    []npmDeadHost{{DomainNames: []string{"gone.example"}, Enabled: 1}},
	}
	res := npmDryRun(t, db, backup)

	for _, want := range []string{":5432", "staff", "wildcard", "gone.example"} {
		if findItem(res.Items, want, npmActionManual) == nil {
			t.Errorf("%q not reported as needing manual action: %+v", want, res.Items)
		}
	}
	if findItem(res.Items, ":9999", npmActionManual) != nil {
		t.Error("disabled stream reported")
	}
	if findItem(res.Items, "le", npmActionManual) != nil {
		t.Error("a Let's Encrypt certificate needs no manual action; the panel issues its own")
	}
	if res.Manual != 4 {
		t.Errorf("manual count = %d, want 4", res.Manual)
	}
}

// Per-host NPM settings the importer cannot carry over become manual lines.
func TestNpmImport_ProxyHostNotes(t *testing.T) {
	notes := proxyHostNotes(npmProxyHost{
		AdvancedConfig: "proxy_set_header X-Foo bar;",
		Locations:      []npmLocation{{Path: "/api"}},
		AccessListID:   3,
		CertificateID:  "12",
		CachingEnabled: true,
		BlockExploits:  true,
		HSTSEnabled:    true,
	})
	if len(notes) != 7 {
		t.Fatalf("got %d notes, want 7: %v", len(notes), notes)
	}
	if n := proxyHostNotes(npmProxyHost{CertificateID: "0"}); len(n) != 0 {
		t.Errorf("plain host produced notes: %v", n)
	}
}

// domainAlreadyMapped is what makes the dry run predict a duplicate rejection.
func TestNpmImport_DomainAlreadyMapped(t *testing.T) {
	db := newNpmTestDB(t)
	ctx := context.Background()
	if !domainAlreadyMapped(ctx, db, "TAKEN.example") {
		t.Error("existing domain not detected (case-insensitive)")
	}
	if domainAlreadyMapped(ctx, db, "free.example") {
		t.Error("unknown domain reported as mapped")
	}
}

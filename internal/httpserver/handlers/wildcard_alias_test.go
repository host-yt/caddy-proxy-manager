package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/view"
)

// A "*.zone" alias is accepted only on a wildcard route of that exact zone;
// anything else is refused with a message instead of silently dropped.
func TestSanitizeAliasesWildcard(t *testing.T) {
	got, err := sanitizeAliases("*.shop.example, www.shop.example", "shop.example", "shop.example")
	if err != nil || got != "*.shop.example,www.shop.example" {
		t.Fatalf("wildcard alias on its zone: got %q, %v", got, err)
	}
	for _, tc := range []struct{ raw, zone, want string }{
		{"*.shop.example", "", "needs wildcard DNS-01"},
		{"*.other.example", "shop.example", "only *.shop.example"},
		{"*.sub.shop.example", "shop.example", "only *.shop.example"},
		{"a.*.shop.example", "shop.example", "only *.shop.example"},
		{"*shop.example", "shop.example", "only *.shop.example"},
	} {
		if _, err := sanitizeAliases(tc.raw, "shop.example", tc.zone); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q zone %q: err = %v, want %q", tc.raw, tc.zone, err, tc.want)
		}
	}
	if got := wildcardAliasZone(false, "shop.example"); got != "" {
		t.Errorf("disabled wildcard still yields zone %q", got)
	}
}

// A failed alias save must say why on the page, not re-render the submitted
// value as if it had been stored.
func TestHostEditShowsAliasError(t *testing.T) {
	tpls, err := view.LoadAdminTemplates()
	if err != nil {
		t.Fatalf("load admin templates: %v", err)
	}
	d := hostEditData{
		baseAdminData: baseAdminData{Role: "admin", CSRF: "csrf", CSPNonce: "nonce"},
		RouteID:       44,
		Domain:        "shop.example",
		Aliases:       "*.shop.example",
		FieldErrors:   map[string]string{"aliases": "aliases: wildcard alias needs DNS-01"},
	}
	var buf bytes.Buffer
	if err := tpls.Render(&buf, "hosts_edit", fillBreadcrumbs("hosts_edit", d)); err != nil {
		t.Fatalf("render hosts_edit: %v", err)
	}
	if !strings.Contains(buf.String(), "aliases: wildcard alias needs DNS-01") {
		t.Error("alias validation error is not rendered")
	}
}

// Wildcard subdomains never go through on-demand: the automate cert serves
// them. An ask allowance would mint one cert per random subdomain (LE limit).
func TestAskDeniesWildcardSubdomain(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	for _, s := range []string{
		`CREATE TABLE routes (id INTEGER PRIMARY KEY, domain TEXT, aliases TEXT, aliases_verified TEXT,
		   status TEXT, ssl_enabled INTEGER, domain_verified INTEGER)`,
		`CREATE TABLE caddy_nodes (id INTEGER PRIMARY KEY, tunnel_transport TEXT,
		   tunnel_wstunnel_port INTEGER, tunnel_endpoint TEXT)`,
		`INSERT INTO routes VALUES (44, 'shop.example', '*.shop.example', '*.shop.example', 'active', 1, 1)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
	h := &AskHandler{DB: func() *sql.DB { return db }}
	ctx := context.Background()
	if h.domainAllowed(ctx, db, "demo.shop.example") {
		t.Error("wildcard subdomain allowed on-demand: one cert per subdomain")
	}
	if !h.domainAllowed(ctx, db, "shop.example") {
		t.Error("verified apex denied")
	}
}

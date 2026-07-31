package handlers

import (
	"context"
	"database/sql"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
)

// FINDING 1 (r13): an alias-only edit is a hostname claim. Keying the matcher
// diff off domain+path alone let an owner bolt an unregistered victim hostname
// onto a route that stayed flagged verified.
func TestAliasAdditionCountsAsMatcherChange(t *testing.T) {
	cases := []struct {
		name                           string
		oldDomain, oldPath, oldAliases string
		domain, path, aliases          string
		want                           bool
	}{
		{"nothing changed", "a.example", "", "x.example", "a.example", "", "x.example", false},
		{"alias added", "a.example", "", "", "a.example", "", "victim.example", true},
		{"alias added next to an existing one", "a.example", "", "x.example",
			"a.example", "", "x.example,victim.example", true},
		{"alias removed only", "a.example", "", "x.example,y.example", "a.example", "", "x.example", false},
		{"alias reordered", "a.example", "", "x.example,y.example", "a.example", "", "y.example, x.example", false},
		{"domain change still counts", "a.example", "", "", "b.example", "", "", true},
		{"path change still counts", "a.example", "", "", "a.example", "/api", "", true},
	}
	for _, tc := range cases {
		got := matcherChangedForUpdate(tc.oldDomain, tc.oldPath, tc.oldAliases, tc.domain, tc.path, tc.aliases)
		if got != tc.want {
			t.Errorf("%s: matcherChangedForUpdate = %v, want %v", tc.name, got, tc.want)
		}
	}

	// A scoped admin adding an alias must therefore re-prove ownership.
	h := limitedAdminHandlers(hostsScopeDB(t))
	ctx := context.Background()
	changed := matcherChangedForUpdate("owned.example", "", "", "owned.example", "", "victim.example")
	for _, sess := range []*auth.Session{restrictedSess, resellerSess} {
		if !h.verificationResetRequired(ctx, sess, changed) {
			t.Errorf("user %d kept domain_verified across an alias-only edit", sess.UserID)
		}
	}
}

// FINDING 1 (r13): an added alias starts unproven even when the route keeps its
// other, already-proven aliases; a removed alias drops its proof.
func TestKeepProvenHosts(t *testing.T) {
	if got := keepProvenHosts("x.example,y.example", "x.example,victim.example"); got != "x.example" {
		t.Errorf("keepProvenHosts = %q, want %q", got, "x.example")
	}
	if got := keepProvenHosts("", "victim.example"); got != "" {
		t.Errorf("added alias inherited proof: %q", got)
	}
	if got := keepProvenHosts("x.example", ""); got != "" {
		t.Errorf("proof survived alias removal: %q", got)
	}
}

// FINDING 1 (r13): the cert ask endpoint must not treat an unproven alias as
// verified through its parent route - that is the takeover, one handshake away
// from a Let's Encrypt certificate for a hostname the caller never owned.
func TestAskDeniesUnverifiedAlias(t *testing.T) {
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
		// Attacker route: verified primary, victim hostname bolted on as an alias.
		`INSERT INTO routes (id, domain, aliases, aliases_verified, status, ssl_enabled, domain_verified)
		   VALUES (1, 'owned.example', 'victim.example,proven.example', 'proven.example', 'active', 1, 1)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
	h := &AskHandler{DB: func() *sql.DB { return db }}
	ctx := context.Background()

	if h.domainAllowed(ctx, db, "victim.example") {
		t.Error("unproven alias was cert-eligible via the parent route")
	}
	if !h.domainAllowed(ctx, db, "proven.example") {
		t.Error("proven alias lost its certificate eligibility")
	}
	if !h.domainAllowed(ctx, db, "owned.example") {
		t.Error("verified primary domain was denied")
	}
}

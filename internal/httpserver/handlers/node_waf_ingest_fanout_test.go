package handlers

import (
	"context"
	"database/sql"
	"log/slog"
	"testing"

	_ "modernc.org/sqlite"
)

// TestWAFRouteIndex_FanoutAndAliases covers the active-active case: a route
// anchored on node 1 and fanned out to node 2 must still resolve when node 2
// ships the event, otherwise the event lands with a NULL route_id and drops out
// of the per-route WAF view, scoped-admin visibility and per-route pruning.
func TestWAFRouteIndex_FanoutAndAliases(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	stmts := []string{
		`CREATE TABLE routes (id INTEGER PRIMARY KEY, caddy_node_id INTEGER, domain TEXT,
			path_prefix TEXT, aliases_verified TEXT, status TEXT)`,
		`CREATE TABLE route_node_assignments (route_id INTEGER, node_id INTEGER)`,
		`INSERT INTO routes VALUES (1, 1, 'ha.example', '', 'www.ha.example', 'active')`,
		`INSERT INTO routes VALUES (2, 1, 'ha.example', '/api', '', 'active')`,
		`INSERT INTO routes VALUES (3, 3, 'other.example', '', '', 'active')`,
		`INSERT INTO route_node_assignments VALUES (1, 2), (2, 2)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("schema %q: %v", s, err)
		}
	}

	h := &NodeWAFIngestHandler{DB: func() *sql.DB { return db }, Logger: slog.Default()}
	idx, err := h.loadRouteIndex(context.Background(), 2)
	if err != nil {
		t.Fatalf("load index: %v", err)
	}
	cases := []struct {
		host, uri string
		want      int64
	}{
		{"ha.example", "/", 1},
		{"www.ha.example", "/", 1},       // proven alias of the fan-out route
		{"ha.example", "/api/orders", 2}, // longest prefix still wins
		{"other.example", "/", 0},        // route this node does not serve
		{"unproven.ha.example", "/", 0},  // alias without proof
	}
	for _, c := range cases {
		if got := idx.resolve(c.host, c.uri); got != c.want {
			t.Errorf("resolve(%q,%q) = %d, want %d", c.host, c.uri, got, c.want)
		}
	}
}

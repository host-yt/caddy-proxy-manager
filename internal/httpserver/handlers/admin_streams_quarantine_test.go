package handlers

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// quarantineTestDB builds the minimal schema the stream write path touches on
// an in-memory SQLite DB, so the un-quarantine logic is covered without MySQL.
func quarantineTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })

	prev := store.Driver()
	store.SetDriver("sqlite3")
	t.Cleanup(func() { store.SetDriver(prev) })

	stmts := []string{
		`CREATE TABLE caddy_nodes (id INTEGER PRIMARY KEY, public_ip TEXT, wg_ip TEXT,
		   api_url TEXT, public_hostname TEXT, tunnel_subnet TEXT)`,
		`CREATE TABLE settings ("key" TEXT PRIMARY KEY, value TEXT)`,
		`CREATE TABLE services (id INTEGER PRIMARY KEY, backend_ip TEXT)`,
		`CREATE TABLE stream_routes (id INTEGER PRIMARY KEY, service_id INTEGER, caddy_node_id INTEGER,
		   protocol TEXT, listen_port INTEGER, upstream_port INTEGER, status TEXT,
		   match_mode TEXT, match_values TEXT, lb_policy TEXT,
		   proxy_proto_in TEXT, proxy_proto_out TEXT, cidr_allow TEXT, cidr_deny TEXT,
		   backend_ip_override TEXT, quarantined_at TIMESTAMP, quarantine_reason TEXT,
		   updated_at TIMESTAMP)`,
		`CREATE TABLE stream_upstreams (id INTEGER PRIMARY KEY, stream_route_id INTEGER,
		   address TEXT, weight INTEGER, sort_order INTEGER)`,
		`INSERT INTO caddy_nodes (id, public_ip, wg_ip, api_url, public_hostname, tunnel_subnet)
		 VALUES (1, '203.0.113.7', '10.66.0.5', 'http://10.66.0.5:2019', 'node1.example.com', '')`,
		`INSERT INTO services (id, backend_ip) VALUES (1, '10.0.0.5')`,
		`INSERT INTO stream_routes (id, service_id, caddy_node_id, protocol, listen_port,
		   upstream_port, status, quarantined_at, quarantine_reason)
		 VALUES (1, 1, 1, 'tcp', 5000, 2019, 'active', '2026-07-01 00:00:00',
		         'migration 00137: upstream port 2019 is the node admin API')`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("schema %q: %v", s, err)
		}
	}
	return db
}

// quarantineState returns (quarantined, reason) for a stream.
func quarantineState(t *testing.T, db *sql.DB, id int64) (bool, string) {
	t.Helper()
	var at sql.NullString
	var reason sql.NullString
	if err := db.QueryRow(
		"SELECT quarantined_at, quarantine_reason FROM stream_routes WHERE id = ?", id).
		Scan(&at, &reason); err != nil {
		t.Fatalf("read quarantine state: %v", err)
	}
	return at.Valid && at.String != "", reason.String
}

func testStreamUpdate(dest streamDestination) streamUpdate {
	return streamUpdate{
		MatchMode: "any", LBPolicy: "round_robin",
		ProxyProtoIn: "none", ProxyProtoOut: "none",
		Dest: dest, ServiceBackendIP: "10.0.0.5",
	}
}

// The operator fixes the destination: the same save that stores it must lift
// the quarantine, otherwise the stream is stuck forever.
func TestSaveStreamUpdateClearsQuarantineOnSafeDestination(t *testing.T) {
	db := quarantineTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if q, reason := quarantineState(t, db, 1); !q || reason == "" {
		t.Fatalf("fixture must start quarantined with a reason, got %v %q", q, reason)
	}
	err := saveStreamUpdate(context.Background(), db, logger, 1,
		testStreamUpdate(streamDestination{BackendIP: "10.0.0.5", UpstreamPort: 8080}))
	if err != nil {
		t.Fatalf("save with safe destination: %v", err)
	}
	if q, reason := quarantineState(t, db, 1); q || reason != "" {
		t.Errorf("quarantine not cleared: quarantined=%v reason=%q", q, reason)
	}
	var port int
	if err := db.QueryRow("SELECT upstream_port FROM stream_routes WHERE id = 1").Scan(&port); err != nil || port != 8080 {
		t.Errorf("destination not persisted: port=%d err=%v", port, err)
	}
}

// Editing to another unsafe destination must be refused and leave the row parked.
func TestSaveStreamUpdateKeepsQuarantineOnUnsafeDestination(t *testing.T) {
	db := quarantineTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	cases := []struct {
		name string
		dest streamDestination
	}{
		{"admin api port", streamDestination{BackendIP: "10.0.0.5", UpstreamPort: 2019}},
		{"node public ip", streamDestination{BackendIP: "203.0.113.7", UpstreamPort: 8080}},
		{"node wg ip", streamDestination{BackendIP: "10.66.0.5", UpstreamPort: 8080}},
		{"loopback", streamDestination{BackendIP: "127.0.0.1", UpstreamPort: 8080}},
		{"unsafe extra upstream", streamDestination{BackendIP: "10.0.0.5", UpstreamPort: 8080,
			Upstreams: []upstreamEntry{{Address: "203.0.113.7:8080", Weight: 1}}}},
	}
	for _, tc := range cases {
		err := saveStreamUpdate(context.Background(), db, logger, 1, testStreamUpdate(tc.dest))
		if err == nil {
			t.Errorf("%s: expected the edit to be rejected", tc.name)
		}
		q, reason := quarantineState(t, db, 1)
		if !q {
			t.Fatalf("%s: quarantine was lifted without a safe destination", tc.name)
		}
		if reason == "" {
			t.Errorf("%s: reason must stay retrievable for display", tc.name)
		}
	}
}

// Re-check re-runs the real screen: it clears only when the stored destination
// now passes, and refreshes the reason when it does not.
func TestRecheckStreamQuarantine(t *testing.T) {
	db := quarantineTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()

	cleared, reason, err := recheckStreamQuarantine(ctx, db, logger, 1)
	if err != nil {
		t.Fatalf("recheck: %v", err)
	}
	if cleared {
		t.Fatal("re-check cleared a still-unsafe destination")
	}
	if reason == "" {
		t.Error("re-check must record why the row stays quarantined")
	}
	if q, stored := quarantineState(t, db, 1); !q || stored != reason {
		t.Errorf("fresh reason not persisted: quarantined=%v stored=%q", q, stored)
	}

	// The destination becomes safe without the row changing (node decommissioned).
	if _, err := db.Exec("DELETE FROM caddy_nodes WHERE id = 1"); err != nil {
		t.Fatalf("delete node: %v", err)
	}
	if _, err := db.Exec("UPDATE stream_routes SET upstream_port = 8080 WHERE id = 1"); err != nil {
		t.Fatalf("fix port: %v", err)
	}
	cleared, _, err = recheckStreamQuarantine(ctx, db, logger, 1)
	if err != nil {
		t.Fatalf("recheck after fix: %v", err)
	}
	if !cleared {
		t.Fatal("re-check did not clear a now-safe destination")
	}
	if q, _ := quarantineState(t, db, 1); q {
		t.Error("quarantine flag still set after a passing re-check")
	}
}

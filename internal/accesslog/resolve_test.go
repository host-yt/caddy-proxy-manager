package accesslog

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// openResolveTestDB builds the minimal schema the node-scoped resolver and the
// ingest handler touch. sqlite keeps the test hermetic (no TEST_DB_DSN).
func openResolveTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	stmts := []string{
		`CREATE TABLE routes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			caddy_node_id INTEGER,
			domain TEXT NOT NULL,
			path_prefix TEXT,
			aliases_verified TEXT,
			status TEXT NOT NULL DEFAULT 'active'
		)`,
		`CREATE TABLE route_node_assignments (
			route_id INTEGER NOT NULL,
			node_id INTEGER NOT NULL
		)`,
		`CREATE TABLE host_access_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			route_id INTEGER NOT NULL,
			ts DATETIME, method TEXT, uri TEXT, status INTEGER,
			latency_ms INTEGER, remote_ip TEXT, user_agent TEXT,
			bytes_resp INTEGER, bytes_req INTEGER, proto TEXT,
			country TEXT, asn_org TEXT
		)`,
		`CREATE TABLE log_rollups (
			route_id INTEGER NOT NULL, bucket_start DATETIME NOT NULL,
			requests INTEGER, errors_4xx INTEGER, errors_5xx INTEGER,
			latency_sum_ms INTEGER, latency_max_ms INTEGER,
			bytes_resp INTEGER, bytes_req INTEGER,
			PRIMARY KEY (route_id, bucket_start)
		)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}
	return db
}

func insertRoute(t *testing.T, db *sql.DB, nodeID int64, domain, prefix, aliasesVerified, status string) int64 {
	t.Helper()
	res, err := db.Exec(
		`INSERT INTO routes (caddy_node_id, domain, path_prefix, aliases_verified, status) VALUES (?,?,?,?,?)`,
		nodeID, domain, prefix, aliasesVerified, status)
	if err != nil {
		t.Fatalf("insert route: %v", err)
	}
	id, _ := res.LastInsertId()
	return id
}

// TestNodeRouteIndex_IsolatesNodes proves a node only ever resolves routes it
// serves: node 2 must not be able to attribute a log line to node 1's route.
func TestNodeRouteIndex_IsolatesNodes(t *testing.T) {
	db := openResolveTestDB(t)
	ctx := context.Background()
	victim := insertRoute(t, db, 1, "victim.example", "", "", "active")

	idx, err := LoadNodeRouteIndex(ctx, db, 2)
	if err != nil {
		t.Fatalf("load index: %v", err)
	}
	if id, ok := idx.Resolve("victim.example", "/"); ok {
		t.Fatalf("node 2 resolved node 1's route %d (want drop)", id)
	}

	own, err := LoadNodeRouteIndex(ctx, db, 1)
	if err != nil {
		t.Fatalf("load index: %v", err)
	}
	if id, ok := own.Resolve("victim.example", "/"); !ok || id != victim {
		t.Fatalf("node 1 resolve = %d,%v want %d,true", id, ok, victim)
	}
}

// TestNodeRouteIndex_LongestPathPrefix proves several routes sharing a domain
// are told apart by path, instead of the old "LIMIT 1" pick.
func TestNodeRouteIndex_LongestPathPrefix(t *testing.T) {
	db := openResolveTestDB(t)
	bare := insertRoute(t, db, 1, "shop.example", "", "", "active")
	api := insertRoute(t, db, 1, "shop.example", "/api", "", "active")
	deep := insertRoute(t, db, 1, "shop.example", "/api/v2", "", "active")

	idx, err := LoadNodeRouteIndex(context.Background(), db, 1)
	if err != nil {
		t.Fatalf("load index: %v", err)
	}
	cases := []struct {
		host, uri string
		want      int64
	}{
		{"shop.example", "/", bare},
		{"shop.example", "/img/logo.png", bare},
		{"shop.example", "/api/orders", api},
		{"shop.example", "/api/v2/orders?page=2", deep},
		{"SHOP.example:443", "/api/v2/x", deep},
		{"other.example", "/api", 0},
	}
	for _, c := range cases {
		got, ok := idx.Resolve(c.host, c.uri)
		if c.want == 0 {
			if ok {
				t.Errorf("%s%s resolved to %d, want drop", c.host, c.uri, got)
			}
			continue
		}
		if !ok || got != c.want {
			t.Errorf("%s%s = %d,%v want %d,true", c.host, c.uri, got, ok, c.want)
		}
	}
}

// TestNodeRouteIndex_FanoutAndAliases covers active-active fan-out peers and
// proven aliases; unproven aliases never reach a node's host matcher, so they
// must not resolve either.
func TestNodeRouteIndex_FanoutAndAliases(t *testing.T) {
	db := openResolveTestDB(t)
	ctx := context.Background()
	rid := insertRoute(t, db, 1, "ha.example", "", "www.ha.example, cdn.ha.example", "active")
	if _, err := db.Exec(`INSERT INTO route_node_assignments (route_id, node_id) VALUES (?, 2)`, rid); err != nil {
		t.Fatalf("assign: %v", err)
	}
	disabled := insertRoute(t, db, 2, "off.example", "", "", "disabled")
	_ = disabled

	peer, err := LoadNodeRouteIndex(ctx, db, 2)
	if err != nil {
		t.Fatalf("load index: %v", err)
	}
	if id, ok := peer.Resolve("ha.example", "/"); !ok || id != rid {
		t.Fatalf("fan-out peer resolve = %d,%v want %d,true", id, ok, rid)
	}
	if id, ok := peer.Resolve("cdn.ha.example", "/"); !ok || id != rid {
		t.Fatalf("verified alias resolve = %d,%v want %d,true", id, ok, rid)
	}
	if _, ok := peer.Resolve("unproven.ha.example", "/"); ok {
		t.Fatal("unproven alias resolved; want drop")
	}
	if _, ok := peer.Resolve("off.example", "/"); ok {
		t.Fatal("disabled route resolved; want drop")
	}
}

// TestIngest_CrossNodePoisoningRejected is the end-to-end regression: an
// authenticated node-agent POSTing a log line for a host served by a different
// node must not create a row on that other node's route.
func TestIngest_CrossNodePoisoningRejected(t *testing.T) {
	db := openResolveTestDB(t)
	victim := insertRoute(t, db, 1, "victim.example", "", "", "active")
	attackerRoute := insertRoute(t, db, 2, "attacker.example", "", "", "active")

	getDB := func() *sql.DB { return db }
	h := &IngestHandler{
		Store:  New(getDB, 100),
		Broker: NewBroker(),
		Logger: slog.Default(),
		ResolveRoutes: func(ctx context.Context, nodeID int64) (NodeRouteIndex, error) {
			return LoadNodeRouteIndex(ctx, db, nodeID)
		},
		AuthNode: func(ctx context.Context, token string) (int64, bool) {
			if token == "node2" {
				return 2, true
			}
			return 0, false
		},
	}

	body := `{"ts":1700000000,"status":200,"duration":0.01,"size":10,"request":{"method":"GET","uri":"/","host":"victim.example","client_ip":"1.2.3.4"}}
{"ts":1700000000,"status":200,"duration":0.01,"size":10,"request":{"method":"GET","uri":"/","host":"attacker.example","client_ip":"1.2.3.4"}}`
	req := httptest.NewRequest(http.MethodPost, "/internal/access-log", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer node2")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}

	var victimRows, ownRows int
	if err := db.QueryRow("SELECT COUNT(*) FROM host_access_log WHERE route_id = ?", victim).Scan(&victimRows); err != nil {
		t.Fatalf("count victim: %v", err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM host_access_log WHERE route_id = ?", attackerRoute).Scan(&ownRows); err != nil {
		t.Fatalf("count own: %v", err)
	}
	if victimRows != 0 {
		t.Errorf("node 2 wrote %d rows onto node 1's route; want 0", victimRows)
	}
	if ownRows != 1 {
		t.Errorf("node 2 wrote %d rows onto its own route; want 1", ownRows)
	}
}

// TestIngest_UnauthenticatedRejected keeps the 401 contract on the publicly
// reachable ingest path.
func TestIngest_UnauthenticatedRejected(t *testing.T) {
	h := &IngestHandler{
		Logger:   slog.Default(),
		AuthNode: func(ctx context.Context, token string) (int64, bool) { return 0, false },
	}
	req := httptest.NewRequest(http.MethodPost, "/internal/access-log", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

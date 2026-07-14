package routes

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// openTestDB opens a real DB using TEST_DB_DSN or skips.
// Only runs when the test environment has a live MariaDB.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set - skipping DB-backed test")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("DB not reachable: %v", err)
	}
	return db
}

// insertTestNodes inserts two caddy_nodes with FK checks off and returns their
// IDs. Callers must clean up via the returned cleanup func.
func insertTestNodes(t *testing.T, db *sql.DB, ctx context.Context) (primaryID, peerID int64, cleanup func()) {
	t.Helper()
	// Disable FK checks so we don't need to insert node_groups first.
	if _, err := db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0"); err != nil {
		t.Fatalf("disable FK checks: %v", err)
	}
	tag := fmt.Sprintf("testfanout_%d", time.Now().UnixNano())

	res, err := db.ExecContext(ctx,
		`INSERT INTO caddy_nodes (name, api_url, node_group_id, current_routes)
		 VALUES (?, 'http://10.0.0.1:2019', 9999, 5)`, tag+"-primary")
	if err != nil {
		t.Fatalf("insert primary node: %v", err)
	}
	primaryID, _ = res.LastInsertId()

	res, err = db.ExecContext(ctx,
		`INSERT INTO caddy_nodes (name, api_url, node_group_id, current_routes)
		 VALUES (?, 'http://10.0.0.2:2019', 9999, 3)`, tag+"-peer")
	if err != nil {
		t.Fatalf("insert peer node: %v", err)
	}
	peerID, _ = res.LastInsertId()

	cleanup = func() {
		_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0")
		_, _ = db.ExecContext(ctx, "DELETE FROM caddy_nodes WHERE id IN (?, ?)", primaryID, peerID)
		_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=1")
	}
	return primaryID, peerID, cleanup
}

// TestFanOutDeleteDecrementsAllNodeCounters proves that deleting a fan-out
// route decrements the primary node counter AND each assigned-peer counter.
// Requires TEST_DB_DSN pointing at a fully-migrated MariaDB instance.
func TestFanOutDeleteDecrementsAllNodeCounters(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	ctx := context.Background()

	primaryID, peerID, cleanupNodes := insertTestNodes(t, db, ctx)
	defer cleanupNodes()

	// Insert a service, route and assignment with FK checks off.
	// The service row must exist: Delete resolves ownership via an INNER JOIN.
	_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0")
	res, err := db.ExecContext(ctx,
		`INSERT INTO services (client_id, name, backend_ip, allowed_port_start,
		   allowed_port_end, plan_id, node_group_id)
		 VALUES (9999, 'fanout-del-test', '10.9.9.9', 1, 65535, 9999, 9999)`)
	if err != nil {
		t.Fatalf("insert service: %v", err)
	}
	serviceID, _ := res.LastInsertId()
	res, err = db.ExecContext(ctx,
		`INSERT INTO routes (service_id, caddy_node_id, domain, upstream_port, upstream_scheme,
		   ssl_enabled, status, kind)
		 VALUES (?, ?, ?, 8080, 'http', 0, 'pending_dns', 'proxy')`,
		serviceID, primaryID, fmt.Sprintf("test%d.example.com", time.Now().UnixNano()))
	if err != nil {
		t.Fatalf("insert route: %v", err)
	}
	routeID, _ := res.LastInsertId()

	if _, err := db.ExecContext(ctx,
		`INSERT INTO route_node_assignments (route_id, node_id) VALUES (?, ?)`,
		routeID, peerID); err != nil {
		t.Fatalf("insert assignment: %v", err)
	}
	_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=1")

	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0")
		_, _ = db.ExecContext(ctx, "DELETE FROM route_node_assignments WHERE route_id = ?", routeID)
		_, _ = db.ExecContext(ctx, "DELETE FROM routes WHERE id = ?", routeID)
		_, _ = db.ExecContext(ctx, "DELETE FROM services WHERE id = ?", serviceID)
		_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=1")
	})

	// Invoke Delete through the Service. clientID=0 skips ownership check.
	svc := &Service{DB: db}
	if err := svc.Delete(ctx, 0, routeID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Assert primary counter decremented: 5 → 4.
	var primaryCount, peerCount int
	if err := db.QueryRowContext(ctx,
		"SELECT current_routes FROM caddy_nodes WHERE id = ?", primaryID,
	).Scan(&primaryCount); err != nil {
		t.Fatalf("read primary counter: %v", err)
	}
	if err := db.QueryRowContext(ctx,
		"SELECT current_routes FROM caddy_nodes WHERE id = ?", peerID,
	).Scan(&peerCount); err != nil {
		t.Fatalf("read peer counter: %v", err)
	}
	if primaryCount != 4 {
		t.Errorf("primary counter: got %d, want 4 (was 5)", primaryCount)
	}
	if peerCount != 2 {
		t.Errorf("peer counter: got %d, want 2 (was 3)", peerCount)
	}

	// Assert assignments row was cleaned up.
	var assignCount int
	_ = db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM route_node_assignments WHERE route_id = ?", routeID,
	).Scan(&assignCount)
	if assignCount != 0 {
		t.Errorf("route_node_assignments not cleaned up: %d rows remain", assignCount)
	}
}

// TestFanOutNodesExcludesPrimary proves that fanOutNodes excludes the primary
// node from its result set. Requires TEST_DB_DSN.
func TestFanOutNodesExcludesPrimary(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	ctx := context.Background()

	primaryID, peerID, cleanupNodes := insertTestNodes(t, db, ctx)
	defer cleanupNodes()

	_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0")
	res, err := db.ExecContext(ctx,
		`INSERT INTO routes (service_id, caddy_node_id, domain, upstream_port, upstream_scheme,
		   ssl_enabled, status, kind)
		 VALUES (9999, ?, ?, 8080, 'http', 0, 'pending_dns', 'proxy')`,
		primaryID, fmt.Sprintf("fontest%d.example.com", time.Now().UnixNano()))
	if err != nil {
		t.Fatalf("insert route: %v", err)
	}
	routeID, _ := res.LastInsertId()
	// Insert BOTH the primary node and the peer into the assignments table.
	for _, nid := range []int64{primaryID, peerID} {
		_, _ = db.ExecContext(ctx,
			"INSERT IGNORE INTO route_node_assignments (route_id, node_id) VALUES (?, ?)", routeID, nid)
	}
	_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=1")

	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0")
		_, _ = db.ExecContext(ctx, "DELETE FROM route_node_assignments WHERE route_id = ?", routeID)
		_, _ = db.ExecContext(ctx, "DELETE FROM routes WHERE id = ?", routeID)
		_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=1")
	})

	svc := &Service{DB: db}
	peers, err := svc.fanOutNodes(ctx, routeID, primaryID)
	if err != nil {
		t.Fatalf("fanOutNodes: %v", err)
	}
	// Must not include primary.
	for _, id := range peers {
		if id == primaryID {
			t.Errorf("fanOutNodes returned the primary node id %d - should be excluded", primaryID)
		}
	}
	// Must include peerID.
	if len(peers) != 1 || peers[0] != peerID {
		t.Errorf("fanOutNodes = %v, want [%d]", peers, peerID)
	}
}

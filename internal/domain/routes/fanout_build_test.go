package routes

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestBuildRoutesForNodeIncludesFanOutPeers proves the config builder emits a
// route on a fan-out peer node (route_node_assignments) even though the row's
// caddy_node_id anchors it to the primary. Regression for issue #3: peers in
// active_active/failover groups were pushed routes:0 and served NOP.
// Requires TEST_DB_DSN pointing at a fully-migrated MariaDB instance.
func TestBuildRoutesForNodeIncludesFanOutPeers(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	ctx := context.Background()

	primaryID, peerID, cleanupNodes := insertTestNodes(t, db, ctx)
	defer cleanupNodes()

	_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0")
	// buildRoutesForNode INNER JOINs services, so the service row must exist.
	res, err := db.ExecContext(ctx,
		`INSERT INTO services (client_id, name, backend_ip, allowed_port_start,
		   allowed_port_end, plan_id, node_group_id)
		 VALUES (9999, 'fanout-build-test', '10.9.9.9', 1, 65535, 9999, 9999)`)
	if err != nil {
		t.Fatalf("insert service: %v", err)
	}
	serviceID, _ := res.LastInsertId()

	res, err = db.ExecContext(ctx,
		`INSERT INTO routes (service_id, caddy_node_id, domain, upstream_port, upstream_scheme,
		   ssl_enabled, status, kind, domain_verified)
		 VALUES (?, ?, ?, 8080, 'http', 0, 'active', 'proxy', 1)`,
		serviceID, primaryID, fmt.Sprintf("fanbuild%d.example.com", time.Now().UnixNano()))
	if err != nil {
		t.Fatalf("insert route: %v", err)
	}
	routeID, _ := res.LastInsertId()

	if _, err := db.ExecContext(ctx,
		"INSERT INTO route_node_assignments (route_id, node_id) VALUES (?, ?)",
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

	svc := &Service{DB: db}
	has := func(nodeID int64) bool {
		_, ids, err := svc.buildRoutesForNode(ctx, nodeID)
		if err != nil {
			t.Fatalf("buildRoutesForNode(%d): %v", nodeID, err)
		}
		for _, id := range ids {
			if id == routeID {
				return true
			}
		}
		return false
	}

	if !has(primaryID) {
		t.Errorf("anchor node %d missing route %d", primaryID, routeID)
	}
	if !has(peerID) {
		t.Errorf("fan-out peer %d missing route %d (issue #3 regression)", peerID, routeID)
	}
}

package routes

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestBuildRoutesDNSResolverIsNodeScoped proves each fan-out node resolves
// container names via ITS OWN peer-group member, not the primary's peer IP
// (that peer has no interface on the secondary node -> 502 on failover).
// Requires TEST_DB_DSN pointing at a fully-migrated instance.
func TestBuildRoutesDNSResolverIsNodeScoped(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	ctx := context.Background()

	primaryID, peerNodeID, cleanupNodes := insertTestNodes(t, db, ctx)
	defer cleanupNodes()

	_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0")
	groupID := time.Now().UnixNano() % 1000000

	mkPeer := func(nodeID int64, ip string) int64 {
		res, err := db.ExecContext(ctx,
			`INSERT INTO customer_wg_peer (client_id, node_id, peer_group_id, name, pubkey, assigned_ip, status)
			 VALUES (9999, ?, ?, ?, ?, ?, 'active')`,
			nodeID, groupID, fmt.Sprintf("dnspeer-%d-%d", nodeID, groupID), fmt.Sprintf("pk-%d-%d", nodeID, groupID), ip)
		if err != nil {
			t.Fatalf("insert peer: %v", err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	basePeerID := mkPeer(primaryID, "100.96.0.7")
	otherPeerID := mkPeer(peerNodeID, "100.96.1.7")

	res, err := db.ExecContext(ctx,
		`INSERT INTO services (client_id, name, backend_ip, allowed_port_start,
		   allowed_port_end, plan_id, node_group_id)
		 VALUES (9999, 'dnspeer-test', '10.9.9.9', 1, 65535, 9999, 9999)`)
	if err != nil {
		t.Fatalf("insert service: %v", err)
	}
	serviceID, _ := res.LastInsertId()

	res, err = db.ExecContext(ctx,
		`INSERT INTO routes (service_id, caddy_node_id, domain, upstream_port, upstream_scheme,
		   ssl_enabled, status, kind, domain_verified,
		   backend_ip_override, via_wg_peer_id, dns_resolver_via_wg_peer_id)
		 VALUES (?, ?, ?, 12355, 'http', 0, 'active', 'proxy', 1, 'app', ?, ?)`,
		serviceID, primaryID, fmt.Sprintf("dnspeer%d.example.com", time.Now().UnixNano()),
		basePeerID, basePeerID)
	if err != nil {
		t.Fatalf("insert route: %v", err)
	}
	routeID, _ := res.LastInsertId()

	if _, err := db.ExecContext(ctx,
		"INSERT INTO route_node_assignments (route_id, node_id) VALUES (?, ?)",
		routeID, peerNodeID); err != nil {
		t.Fatalf("insert assignment: %v", err)
	}
	_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=1")

	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0")
		_, _ = db.ExecContext(ctx, "DELETE FROM route_node_assignments WHERE route_id = ?", routeID)
		_, _ = db.ExecContext(ctx, "DELETE FROM routes WHERE id = ?", routeID)
		_, _ = db.ExecContext(ctx, "DELETE FROM services WHERE id = ?", serviceID)
		_, _ = db.ExecContext(ctx, "DELETE FROM customer_wg_peer WHERE id IN (?, ?)", basePeerID, otherPeerID)
		_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=1")
	})

	svc := &Service{DB: db}
	resolverFor := func(nodeID int64) (string, string) {
		built, ids, err := svc.buildRoutesForNode(ctx, nodeID)
		if err != nil {
			t.Fatalf("buildRoutesForNode(%d): %v", nodeID, err)
		}
		for i, id := range ids {
			if id == routeID {
				return built[i].DNSResolverViaWGPeerIP, built[i].UpstreamIP
			}
		}
		t.Fatalf("route %d not built for node %d", routeID, nodeID)
		return "", ""
	}

	if got, up := resolverFor(primaryID); got != "100.96.0.7" || up != "app" {
		t.Errorf("primary node: resolver=%q upstream=%q, want 100.96.0.7 / app", got, up)
	}
	if got, up := resolverFor(peerNodeID); got != "100.96.1.7" || up != "app" {
		t.Errorf("fan-out node: resolver=%q upstream=%q, want 100.96.1.7 / app (node-scoped peer)", got, up)
	}
}

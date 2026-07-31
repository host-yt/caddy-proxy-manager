package routes

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"
)

// insertOrderRoute inserts one route on an explicit domain/alias/path.
func insertOrderRoute(t *testing.T, db *sql.DB, ctx context.Context, nodeID int64,
	domain, aliases, path string, portalProtect bool) int64 {
	t.Helper()
	_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0")
	res, err := db.ExecContext(ctx,
		`INSERT INTO services (client_id, name, backend_ip, allowed_port_start,
		   allowed_port_end, plan_id, node_group_id)
		 VALUES (9999, ?, '10.9.9.9', 1, 65535, 9999, 9999)`,
		fmt.Sprintf("order-%d", time.Now().UnixNano()))
	if err != nil {
		t.Fatalf("insert service: %v", err)
	}
	serviceID, _ := res.LastInsertId()
	res, err = db.ExecContext(ctx,
		`INSERT INTO routes (service_id, caddy_node_id, domain, aliases, path_prefix, upstream_port,
		   upstream_scheme, status, kind, domain_verified, portal_protect)
		 VALUES (?, ?, ?, ?, ?, 8080, 'http', 'active', 'proxy', 1, ?)`,
		serviceID, nodeID, domain, aliases, path, portalProtect)
	if err != nil {
		t.Fatalf("insert route: %v", err)
	}
	routeID, _ := res.LastInsertId()
	if portalProtect {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO route_access_grants (route_id, group_id) VALUES (?, 9999)`, routeID); err != nil {
			t.Fatalf("insert grant: %v", err)
		}
	}
	_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=1")
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0")
		_, _ = db.ExecContext(ctx, "DELETE FROM route_access_grants WHERE route_id = ?", routeID)
		_, _ = db.ExecContext(ctx, "DELETE FROM routes WHERE id = ?", routeID)
		_, _ = db.ExecContext(ctx, "DELETE FROM services WHERE id = ?", serviceID)
		_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=1")
	})
	return routeID
}

// An older catch-all (lower id, emitted first under ORDER BY r.id ASC) must not
// shadow a newer protected subpath on the same host or on a shared alias.
func TestBuildRoutesEmitsProtectedSubpathBeforeCatchAll(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	ctx := context.Background()
	nodeID, _, cleanupNodes := insertTestNodes(t, db, ctx)
	defer cleanupNodes()

	stamp := time.Now().UnixNano()
	domain := fmt.Sprintf("eo%d.example.com", stamp)
	alias := fmt.Sprintf("www-eo%d.example.com", stamp)

	catchAllID := insertOrderRoute(t, db, ctx, nodeID, domain, alias, "", false)
	// Higher id, portal-protected but no verifier configured => deny route.
	protectedID := insertOrderRoute(t, db, ctx, nodeID, domain, alias, "/secure", true)
	if protectedID <= catchAllID {
		t.Fatalf("test setup: protected route must have the higher id (%d <= %d)", protectedID, catchAllID)
	}

	svc := &Service{DB: db}
	built, ids, err := svc.buildRoutesForNode(ctx, nodeID)
	if err != nil {
		t.Fatalf("buildRoutesForNode: %v", err)
	}
	posOf := func(id int64) int {
		for i, v := range ids {
			if v == id {
				return i
			}
		}
		t.Fatalf("route %d not built", id)
		return -1
	}
	pProtected, pCatchAll := posOf(protectedID), posOf(catchAllID)
	if pProtected > pCatchAll {
		t.Fatalf("catch-all (pos %d) precedes protected subpath (pos %d): /secure would be proxied open",
			pCatchAll, pProtected)
	}
	if !built[pProtected].PortalDenyOnMisconfig {
		t.Errorf("protected route must be fail-closed, got %+v", built[pProtected].PortalDenyOnMisconfig)
	}
	// ids must stay aligned with built after the reorder (buildOneRoute relies on it).
	if built[pProtected].PathPrefix != "/secure" || built[pCatchAll].PathPrefix != "" {
		t.Errorf("ids/built misaligned after reorder: %q / %q",
			built[pProtected].PathPrefix, built[pCatchAll].PathPrefix)
	}
}

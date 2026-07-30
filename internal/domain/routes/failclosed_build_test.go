package routes

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"
)

// insertFailClosedRoute creates a service + one route and returns its id.
func insertFailClosedRoute(t *testing.T, db *sql.DB, ctx context.Context, nodeID int64, extraCols, extraVals string, args ...any) int64 {
	t.Helper()
	_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0")
	res, err := db.ExecContext(ctx,
		`INSERT INTO services (client_id, name, backend_ip, allowed_port_start,
		   allowed_port_end, plan_id, node_group_id)
		 VALUES (9999, ?, '10.9.9.9', 1, 65535, 9999, 9999)`,
		fmt.Sprintf("failclosed-%d", time.Now().UnixNano()))
	if err != nil {
		t.Fatalf("insert service: %v", err)
	}
	serviceID, _ := res.LastInsertId()

	q := `INSERT INTO routes (service_id, caddy_node_id, domain, upstream_port, upstream_scheme,
	        status, kind, domain_verified` + extraCols + `)
	      VALUES (?, ?, ?, 8080, 'http', 'active', 'proxy', 1` + extraVals + `)`
	all := append([]any{serviceID, nodeID, fmt.Sprintf("fc%d.example.com", time.Now().UnixNano())}, args...)
	res, err = db.ExecContext(ctx, q, all...)
	if err != nil {
		t.Fatalf("insert route: %v", err)
	}
	routeID, _ := res.LastInsertId()
	_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=1")
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0")
		_, _ = db.ExecContext(ctx, "DELETE FROM routes WHERE id = ?", routeID)
		_, _ = db.ExecContext(ctx, "DELETE FROM services WHERE id = ?", serviceID)
		_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=1")
	})
	return routeID
}

func findBuilt(t *testing.T, svc *Service, ctx context.Context, nodeID, routeID int64) (denyMTLS, denyPortal, requireCert, portalProtect bool) {
	t.Helper()
	built, ids, err := svc.buildRoutesForNode(ctx, nodeID)
	if err != nil {
		t.Fatalf("buildRoutesForNode: %v", err)
	}
	for i, id := range ids {
		if id == routeID {
			return built[i].MTLSDenyOnMisconfig, built[i].PortalDenyOnMisconfig,
				built[i].RequireClientCert, built[i].PortalProtect
		}
	}
	t.Fatalf("route %d not built", routeID)
	return
}

// TestBuildRoutesMTLSFailClosed proves require_client_cert=1 with no usable CA
// yields a deny route (fail closed) and reverts to today's open behaviour only
// when mtls.fail_open=1.
func TestBuildRoutesMTLSFailClosed(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	ctx := context.Background()
	nodeID, _, cleanupNodes := insertTestNodes(t, db, ctx)
	defer cleanupNodes()

	// ssl_enabled=1 but mtls_ca_id NULL -> no CA PEM -> not enforceable.
	routeID := insertFailClosedRoute(t, db, ctx, nodeID,
		", ssl_enabled, require_client_cert", ", 1, 1")

	setFailOpen := func(v string) {
		_, _ = db.ExecContext(ctx,
			"INSERT INTO settings (`key`, value) VALUES ('mtls.fail_open', ?) ON DUPLICATE KEY UPDATE value = ?", v, v)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(ctx, "DELETE FROM settings WHERE `key` = 'mtls.fail_open'") })

	svc := &Service{DB: db}
	setFailOpen("0")
	deny, _, req, _ := findBuilt(t, svc, ctx, nodeID, routeID)
	if !deny {
		t.Error("fail_open=0: unenforceable mTLS route must be denied, not served open")
	}
	if req {
		t.Error("RequireClientCert must be false when no policy can be emitted")
	}

	setFailOpen("1")
	deny, _, _, _ = findBuilt(t, svc, ctx, nodeID, routeID)
	if deny {
		t.Error("fail_open=1: permissive behaviour must be preserved (no deny route)")
	}
}

// TestBuildRoutesPortalFailClosed proves portal_protect=1 with no reachable
// verifier yields a deny route regardless of mtls.fail_open.
func TestBuildRoutesPortalFailClosed(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	ctx := context.Background()
	nodeID, _, cleanupNodes := insertTestNodes(t, db, ctx)
	defer cleanupNodes()

	routeID := insertFailClosedRoute(t, db, ctx, nodeID, ", portal_protect", ", 1")
	// The portal gate needs >=1 grant, else it is intentionally not enabled.
	_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0")
	if _, err := db.ExecContext(ctx,
		`INSERT INTO route_access_grants (route_id, group_id) VALUES (?, 9999)`, routeID); err != nil {
		t.Fatalf("insert grant: %v", err)
	}
	_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=1")
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, "DELETE FROM route_access_grants WHERE route_id = ?", routeID)
	})

	// No PanelInternalHost/Port -> verifier unavailable.
	svc := &Service{DB: db}
	_, denyPortal, _, protect := findBuilt(t, svc, ctx, nodeID, routeID)
	if !denyPortal {
		t.Error("portal-protected route with no verifier must be denied, not served open")
	}
	if protect {
		t.Error("PortalProtect must be false when no dial exists")
	}

	// Verifier configured -> normal gated route, no deny.
	svc = &Service{DB: db, PanelInternalHost: "app", PanelInternalPort: 8080}
	_, denyPortal, _, protect = findBuilt(t, svc, ctx, nodeID, routeID)
	if denyPortal || !protect {
		t.Errorf("with a verifier: want protect=true deny=false, got protect=%v deny=%v", protect, denyPortal)
	}
}

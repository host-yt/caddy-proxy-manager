package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// TestStatusPageTrafficSparkline_NoCrossTenantLeak proves the public status
// page's traffic figure reflects only the requesting client's own routes,
// even when another tenant shares the same caddy node (a4c49fa4 finding).
func TestStatusPageTrafficSparkline_NoCrossTenantLeak(t *testing.T) {
	db := openTestDBHandlers(t)
	defer db.Close()
	ctx := context.Background()

	// DateSub dialect is a package-level global; pin it to mysql so this test
	// is not order-dependent on other tests that flip it to sqlite3.
	prevDriver := store.Driver()
	store.SetDriver("mysql")
	t.Cleanup(func() { store.SetDriver(prevDriver) })

	suffix := time.Now().UnixNano()
	ng := insertRow(t, ctx, db, "node_groups", fmt.Sprintf(
		"INSERT INTO node_groups (name) VALUES ('spg-ng-%d')", suffix))
	node := insertRow(t, ctx, db, "caddy_nodes", fmt.Sprintf(
		`INSERT INTO caddy_nodes (name, api_url, node_group_id)
		 VALUES ('spg-node-%d', 'http://x', %d)`, suffix, ng))
	plan := insertRow(t, ctx, db, "plans", fmt.Sprintf(
		`INSERT INTO plans (name, node_group_id) VALUES ('spg-plan-%d', %d)`, suffix, ng))

	userA := insertRow(t, ctx, db, "users", fmt.Sprintf(
		"INSERT INTO users (email, password_hash, role) VALUES ('spga_%d@x.test', 'x', 'client')", suffix))
	userB := insertRow(t, ctx, db, "users", fmt.Sprintf(
		"INSERT INTO users (email, password_hash, role) VALUES ('spgb_%d@x.test', 'x', 'client')", suffix))
	clientA := insertRow(t, ctx, db, "clients", fmt.Sprintf(
		"INSERT INTO clients (user_id) VALUES (%d)", userA))
	clientB := insertRow(t, ctx, db, "clients", fmt.Sprintf(
		"INSERT INTO clients (user_id) VALUES (%d)", userB))
	svcA := insertRow(t, ctx, db, "services", fmt.Sprintf(
		`INSERT INTO services (client_id, name, backend_ip, allowed_port_start,
		   allowed_port_end, plan_id, node_group_id)
		 VALUES (%d, 'svc-a', '10.0.0.1', 1000, 1010, %d, %d)`, clientA, plan, ng))
	svcB := insertRow(t, ctx, db, "services", fmt.Sprintf(
		`INSERT INTO services (client_id, name, backend_ip, allowed_port_start,
		   allowed_port_end, plan_id, node_group_id)
		 VALUES (%d, 'svc-b', '10.0.0.2', 1000, 1010, %d, %d)`, clientB, plan, ng))
	// Both clients share the same caddy node - the leak vector.
	routeA := insertRow(t, ctx, db, "routes", fmt.Sprintf(
		`INSERT INTO routes (service_id, caddy_node_id, domain, upstream_port)
		 VALUES (%d, %d, 'a-%d.example.test', 80)`, svcA, node, suffix))
	routeB := insertRow(t, ctx, db, "routes", fmt.Sprintf(
		`INSERT INTO routes (service_id, caddy_node_id, domain, upstream_port)
		 VALUES (%d, %d, 'b-%d.example.test', 80)`, svcB, node, suffix))

	today := time.Now().UTC().Truncate(24 * time.Hour)
	if _, err := db.ExecContext(ctx,
		`INSERT INTO log_rollups (route_id, bucket_start, requests) VALUES (?, ?, ?)`,
		routeA, today, 100); err != nil {
		t.Fatalf("insert rollup A: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO log_rollups (route_id, bucket_start, requests) VALUES (?, ?, ?)`,
		routeB, today, 900000); err != nil {
		t.Fatalf("insert rollup B: %v", err)
	}
	defer func() {
		_, _ = db.ExecContext(ctx, "DELETE FROM log_rollups WHERE route_id IN (?, ?)", routeA, routeB)
		_, _ = db.ExecContext(ctx, "DELETE FROM routes WHERE id IN (?, ?)", routeA, routeB)
		_, _ = db.ExecContext(ctx, "DELETE FROM services WHERE id IN (?, ?)", svcA, svcB)
		_, _ = db.ExecContext(ctx, "DELETE FROM clients WHERE id IN (?, ?)", clientA, clientB)
		_, _ = db.ExecContext(ctx, "DELETE FROM users WHERE id IN (?, ?)", userA, userB)
		_, _ = db.ExecContext(ctx, "DELETE FROM caddy_nodes WHERE id = ?", node)
		_, _ = db.ExecContext(ctx, "DELETE FROM plans WHERE id = ?", plan)
		_, _ = db.ExecContext(ctx, "DELETE FROM node_groups WHERE id = ?", ng)
	}()

	h := &StatusPageHandlers{DB: func() *sql.DB { return db }}
	_, valuesJSON := h.trafficSparkline(ctx, db, clientA)

	if strings.Contains(string(valuesJSON), "900000") {
		t.Fatalf("client A traffic sparkline includes client B's request count: %s", valuesJSON)
	}
	if !strings.Contains(string(valuesJSON), "100") {
		t.Fatalf("client A traffic sparkline missing its own request count: %s", valuesJSON)
	}
}

func insertRow(t *testing.T, ctx context.Context, db *sql.DB, table, query string) int64 {
	t.Helper()
	res, err := db.ExecContext(ctx, query)
	if err != nil {
		t.Fatalf("insert into %s: %v", table, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("last insert id for %s: %v", table, err)
	}
	return id
}


package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// openTestDB opens a real MySQL/MariaDB DB using TEST_DB_DSN, or skips - same
// pattern as internal/domain/routes/fanout_counter_test.go.
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

// TestDoctorStoredRoutesInventory proves the R0.3 read-only inventory finds a
// stored row that violates each of the three policies it audits: an HTTP
// target on loopback, a redirect_url with a disallowed placeholder, and a WAF
// directive line today's screen would drop. Requires TEST_DB_DSN.
func TestDoctorStoredRoutesInventory(t *testing.T) {
	db := openTestDB(t)
	// Registered first so it runs LAST (t.Cleanup is LIFO): the row-deleting
	// cleanup below must run against a still-open db, not an already-closed one.
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()

	_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0")
	res, err := db.ExecContext(ctx,
		`INSERT INTO clients (user_id, display_name) VALUES (999999, 'doctor-inventory-test')`)
	if err != nil {
		t.Fatalf("insert client: %v", err)
	}
	clientID, _ := res.LastInsertId()

	res, err = db.ExecContext(ctx,
		`INSERT INTO services (client_id, name, backend_ip, allowed_port_start, allowed_port_end, plan_id, node_group_id)
		 VALUES (?, 'doctor-inventory-test', '10.0.0.9', 1, 65535, 9999, 9999)`, clientID)
	if err != nil {
		t.Fatalf("insert service: %v", err)
	}
	serviceID, _ := res.LastInsertId()

	domain := fmt.Sprintf("doctorinv%d.example.com", time.Now().UnixNano())
	res, err = db.ExecContext(ctx,
		`INSERT INTO routes (service_id, caddy_node_id, domain, upstream_port,
		   backend_ip_override, redirect_url, waf_enabled, waf_directives)
		 VALUES (?, 9999, ?, 80, '127.0.0.1', 'https://evil.example/{env.SECRET}', 1, 'Include /etc/evil.conf')`,
		serviceID, domain)
	if err != nil {
		t.Fatalf("insert route: %v", err)
	}
	routeID, _ := res.LastInsertId()

	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0")
		_, _ = db.ExecContext(ctx, "DELETE FROM routes WHERE id = ?", routeID)
		_, _ = db.ExecContext(ctx, "DELETE FROM services WHERE id = ?", serviceID)
		_, _ = db.ExecContext(ctx, "DELETE FROM clients WHERE id = ?", clientID)
		_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=1")
	})
	_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=1")

	checks := doctorStoredRoutesInventory(ctx, db)

	find := func(name string) *check {
		for i := range checks {
			if checks[i].name == name {
				return &checks[i]
			}
		}
		return nil
	}

	target := find("routes: stored HTTP targets (loopback/managed-node/WG/port 2019)")
	if target == nil || target.status != statusWarn || !strings.Contains(target.detail, fmt.Sprintf("route #%d", routeID)) {
		t.Fatalf("expected the loopback backend to be flagged, got %+v", target)
	}

	ph := find("routes: stored placeholder allow-list")
	if ph == nil || ph.status != statusWarn || !strings.Contains(ph.detail, fmt.Sprintf("route #%d", routeID)) ||
		!strings.Contains(ph.detail, "env.SECRET") {
		t.Fatalf("expected the redirect_url placeholder to be flagged, got %+v", ph)
	}

	waf := find("routes: stored WAF directives")
	if waf == nil || waf.status != statusWarn || !strings.Contains(waf.detail, fmt.Sprintf("route #%d", routeID)) {
		t.Fatalf("expected the WAF directive to be flagged, got %+v", waf)
	}
}

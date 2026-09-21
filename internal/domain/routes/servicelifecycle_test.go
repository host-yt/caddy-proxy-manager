package routes

import (
	"context"
	"database/sql"
	"log/slog"
	"testing"
)

// lifecycleDB seeds one service with three routes: serving, manually disabled,
// and one still waiting for DNS.
func lifecycleDB(t *testing.T) *sql.DB {
	t.Helper()
	db := migratedSQLite(t)
	for _, s := range []string{
		`INSERT INTO node_groups (id, name) VALUES (1, 'g1')`,
		`INSERT INTO caddy_nodes (id, name, api_url, is_enabled, node_group_id) VALUES (1, 'edge1', 'http://127.0.0.1:1', 1, 1)`,
		`INSERT INTO plans (id, name, node_group_id, ssl_enabled, websocket_enabled) VALUES (1, 'p1', 1, 1, 1)`,
		`INSERT INTO services (id, client_id, name, backend_ip, allowed_port_start, allowed_port_end, plan_id, node_group_id, status)
		   VALUES (1, 1, 'svc', '10.0.0.9', 10000, 20000, 1, 1, 'active')`,
		`INSERT INTO routes (id, service_id, caddy_node_id, domain, upstream_port, upstream_scheme,
		   ssl_enabled, status, kind, domain_verified)
		   VALUES (10, 1, 1, 'serving.example', 10001, 'http', 1, 'active', 'proxy', 1)`,
		`INSERT INTO routes (id, service_id, caddy_node_id, domain, upstream_port, upstream_scheme,
		   ssl_enabled, status, kind, domain_verified)
		   VALUES (11, 1, 1, 'offbyhand.example', 10002, 'http', 1, 'disabled', 'proxy', 1)`,
		`INSERT INTO routes (id, service_id, caddy_node_id, domain, upstream_port, upstream_scheme,
		   ssl_enabled, status, kind, domain_verified)
		   VALUES (12, 1, 1, 'waiting.example', 10003, 'http', 1, 'pending_dns', 'proxy', 1)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("seed %q: %v", s, err)
		}
	}
	return db
}

func routeState(t *testing.T, db *sql.DB, id int64) (status, reason string) {
	t.Helper()
	if err := db.QueryRow(
		"SELECT status, COALESCE(disabled_reason,'') FROM routes WHERE id = ?", id).Scan(&status, &reason); err != nil {
		t.Fatalf("route %d: %v", id, err)
	}
	return
}

// HPG-007: suspend never deletes a route, and it records WHY each route is off
// so resume can tell its own work apart from an operator's.
func TestSuspendResumeKeepsManualDisablesOff(t *testing.T) {
	db := lifecycleDB(t)
	svc := &Service{DB: db, Logger: slog.Default(), BgCtx: cancelledCtx()}
	ctx := context.Background()

	if err := svc.SuspendService(ctx, 1); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM routes WHERE service_id = 1").Scan(&n); err != nil || n != 3 {
		t.Fatalf("routes after suspend = %d (err %v), want all 3 rows kept", n, err)
	}
	if st, rs := routeState(t, db, 10); st != "disabled" || rs != DisabledByServiceSuspend {
		t.Errorf("serving route = %s/%s, want disabled/service_suspended", st, rs)
	}
	if st, rs := routeState(t, db, 11); st != "disabled" || rs != "" {
		t.Errorf("manually disabled route = %s/%s, want it untouched", st, rs)
	}

	if err := svc.ResumeService(ctx, 1); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if st, rs := routeState(t, db, 10); st != "active" || rs != "" {
		t.Errorf("suspended route after resume = %s/%s, want active with no reason", st, rs)
	}
	if st, _ := routeState(t, db, 11); st != "disabled" {
		t.Errorf("manually disabled route after resume = %s, want it still disabled", st)
	}
	var svcStatus string
	if err := db.QueryRow("SELECT status FROM services WHERE id = 1").Scan(&svcStatus); err != nil || svcStatus != "active" {
		t.Errorf("service status = %q (err %v), want active", svcStatus, err)
	}
}

// Terminate is the terminal form: routes stop serving, rows survive, and the
// service can neither suspend nor resume afterwards.
func TestTerminateServiceIsFinal(t *testing.T) {
	db := lifecycleDB(t)
	svc := &Service{DB: db, Logger: slog.Default(), BgCtx: cancelledCtx()}
	ctx := context.Background()

	if err := svc.TerminateService(ctx, 1); err != nil {
		t.Fatalf("terminate: %v", err)
	}
	if st, rs := routeState(t, db, 10); st != "disabled" || rs != DisabledByServiceTerminated {
		t.Errorf("route = %s/%s, want disabled/service_terminated", st, rs)
	}
	if err := svc.ResumeService(ctx, 1); err != ErrServiceTerminated {
		t.Errorf("resume of a terminated service = %v, want ErrServiceTerminated", err)
	}
}

// The periodic reconcile used to walk a suspended service's route back to
// serving. advanceRoute now refuses it before any DNS work.
func TestAdvanceRouteHoldsRouteOfSuspendedService(t *testing.T) {
	db := lifecycleDB(t)
	svc := &Service{DB: db, Logger: slog.Default(), BgCtx: cancelledCtx()}
	ctx := context.Background()

	if _, err := db.Exec("UPDATE services SET status = 'suspended' WHERE id = 1"); err != nil {
		t.Fatal(err)
	}
	svc.advanceRoute(ctx, 12) // pending_dns route of the suspended service
	if st, rs := routeState(t, db, 12); st != "disabled" || rs != DisabledByServiceSuspend {
		t.Errorf("route = %s/%s, want disabled/service_suspended", st, rs)
	}
}

func TestSuspendMissingService(t *testing.T) {
	db := lifecycleDB(t)
	svc := &Service{DB: db, Logger: slog.Default(), BgCtx: cancelledCtx()}
	if err := svc.SuspendService(context.Background(), 4242); err != ErrServiceNotFound {
		t.Errorf("err = %v, want ErrServiceNotFound", err)
	}
}

// cancelledCtx keeps post-commit node pushes from dialling the fake node.
func cancelledCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

package routes

import (
	"context"
	"database/sql"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
)

// seedWP1 inserts the node/plan/service scaffolding plus one route and returns
// its id. extra is appended to the routes INSERT column/value lists.
func seedWP1(t *testing.T, db *sql.DB, cols, vals string) int64 {
	t.Helper()
	for _, s := range []string{
		`INSERT INTO node_groups (id, name) VALUES (1, 'g1')`,
		`INSERT INTO caddy_nodes (id, name, api_url, is_enabled, node_group_id) VALUES (1, 'edge1', 'http://n1:2019', 1, 1)`,
		`INSERT INTO plans (id, name, node_group_id) VALUES (1, 'p1', 1)`,
		`INSERT INTO services (id, client_id, name, backend_ip, allowed_port_start, allowed_port_end, plan_id, node_group_id)
		   VALUES (1, 1, 'svc', '10.0.0.9', 1, 65535, 1, 1)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
	q := `INSERT INTO routes (id, service_id, caddy_node_id, domain, upstream_port, upstream_scheme,
	        ssl_enabled, status, kind, domain_verified` + cols + `)
	      VALUES (10, 1, 1, 'owned.example', 8080, 'http', 1, 'active', 'proxy', 1` + vals + `)`
	if _, err := db.Exec(q); err != nil {
		t.Fatalf("insert route: %v", err)
	}
	return 10
}

// HPG-003: protection INTENT and the grant set are separate facts. Removing the
// last grant used to collapse the whole gate, republishing a private route to
// the public internet.
func TestPortalProtectWithNoGrantsDenies(t *testing.T) {
	db := migratedSQLite(t)
	id := seedWP1(t, db, ", portal_protect", ", 1")
	svc := &Service{DB: db, Logger: slog.Default(),
		PanelInternalHost: "panel", PanelInternalPort: 8080}

	built, ids, err := svc.buildRoutesForNode(context.Background(), 1)
	if err != nil {
		t.Fatalf("buildRoutesForNode: %v", err)
	}
	r := pickWP1(t, built, ids, id)
	if !r.PortalDenyOnMisconfig || !r.PortalNoGrants {
		t.Errorf("zero-grant protected route must deny, got deny=%v noGrants=%v protect=%v",
			r.PortalDenyOnMisconfig, r.PortalNoGrants, r.PortalProtect)
	}

	// With a grant the gate is emitted normally.
	if _, err := db.Exec(
		`INSERT INTO route_access_grants (route_id, group_id) VALUES (?, 1)`, id); err != nil {
		t.Fatalf("grant: %v", err)
	}
	built, ids, err = svc.buildRoutesForNode(context.Background(), 1)
	if err != nil {
		t.Fatalf("buildRoutesForNode: %v", err)
	}
	if r := pickWP1(t, built, ids, id); !r.PortalProtect || r.PortalDenyOnMisconfig {
		t.Errorf("granted route must be gated, got protect=%v deny=%v", r.PortalProtect, r.PortalDenyOnMisconfig)
	}
}

// HPG-005: a mandatory policy that cannot be READ is not a policy that does not
// exist. The build must fail rather than publish a config without the gate.
func TestRequiredPolicyReadErrorFailsTheBuild(t *testing.T) {
	for _, table := range []string{"route_basic_auth_users", "mtls_path_rules", "route_location_rules"} {
		t.Run(table, func(t *testing.T) {
			db := migratedSQLite(t)
			seedWP1(t, db, "", "")
			if _, err := db.Exec("DROP TABLE " + table); err != nil {
				t.Fatalf("drop %s: %v", table, err)
			}
			svc := &Service{DB: db, Logger: slog.Default()}
			if _, _, err := svc.buildRoutesForNode(context.Background(), 1); err == nil {
				t.Fatalf("unreadable %s produced a config instead of an error", table)
			}
		})
	}
}

// HPG-009: the quarantine branch audits to the same DB the route iterator is
// reading from. With a single-connection pool that deadlocks until the context
// deadline, so the whole node config is lost.
func TestQuarantineAuditDoesNotDeadlockOnOneConnection(t *testing.T) {
	db := migratedSQLite(t)
	db.SetMaxOpenConns(1) // what store/dbpool.go does for SQLite
	id := seedWP1(t, db, ", custom_config", `, '[{"handler":"reverse_proxy"}]'`)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	built, ids, err := (&Service{DB: db, Logger: slog.Default()}).buildRoutesForNode(ctx, 1)
	if err != nil {
		t.Fatalf("buildRoutesForNode: %v", err)
	}
	if len(built) != 1 {
		t.Fatalf("want the route built and quarantined, got %d", len(built))
	}
	_ = ids
	var n int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM audit_log WHERE action = 'route.custom_handlers.quarantined' AND entity_id = ?`,
		id).Scan(&n); err != nil {
		t.Fatalf("audit count: %v", err)
	}
	if n == 0 {
		t.Error("quarantine was not audited")
	}
}

// HPG-022: the compile outcome has to outlive the log line, or an "active" host
// silently serves a 503 with the cause only in the audit trail.
func TestCompileResultIsPersisted(t *testing.T) {
	db := migratedSQLite(t)
	id := seedWP1(t, db, ", custom_config, redirect_url", `, '[{"handler":"reverse_proxy"}]', ''`)
	svc := &Service{DB: db, Logger: slog.Default()}
	ctx := context.Background()
	if _, _, err := svc.buildRoutesForNode(ctx, 1); err != nil {
		t.Fatalf("buildRoutesForNode: %v", err)
	}
	res, err := svc.CompileResults(ctx, []int64{id})
	if err != nil {
		t.Fatalf("CompileResults: %v", err)
	}
	got, ok := res[id]
	if !ok || got.Status != compileQuarantined {
		t.Fatalf("want a recorded quarantine, got %+v (present=%v)", got, ok)
	}
	if !strings.Contains(got.Reason, "custom handler") {
		t.Errorf("reason must name the cause, got %q", got.Reason)
	}

	// Fixing the route clears the flag on the next compile.
	if _, err := db.Exec(`UPDATE routes SET custom_config = '' WHERE id = ?`, id); err != nil {
		t.Fatalf("fix: %v", err)
	}
	if _, _, err := svc.buildRoutesForNode(ctx, 1); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	res, _ = svc.CompileResults(ctx, []int64{id})
	if res[id].Status != compileOK {
		t.Errorf("repaired route still reads %q", res[id].Status)
	}
}

// HPG-001 at the emission boundary: a stored placeholder must quarantine the
// route instead of riding along into the node config.
func TestStoredPlaceholderQuarantinesAtCompile(t *testing.T) {
	db := migratedSQLite(t)
	id := seedWP1(t, db, ", custom_headers",
		`, '{"X-Leak":"{file./etc/caddy/secrets.env}"}'`)
	svc := &Service{DB: db, Logger: slog.Default()}
	ctx := context.Background()
	if _, _, err := svc.buildRoutesForNode(ctx, 1); err != nil {
		t.Fatalf("buildRoutesForNode: %v", err)
	}
	res, _ := svc.CompileResults(ctx, []int64{id})
	if res[id].Status != compileQuarantined || !strings.Contains(res[id].Reason, "placeholder") {
		t.Fatalf("unsafe stored header was not quarantined: %+v", res[id])
	}
}

func pickWP1(t *testing.T, built []caddyapi.Route, ids []int64, id int64) caddyapi.Route {
	t.Helper()
	for i, got := range ids {
		if got == id {
			return built[i]
		}
	}
	t.Fatalf("route %d not built", id)
	return caddyapi.Route{}
}

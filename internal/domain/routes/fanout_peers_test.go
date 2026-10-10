package routes

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"testing"
)

// seedFanoutRoute builds a SQLite fixture: client 1 -> service 1, anchor node 1,
// fan-out peer node 2, route 1 anchored on node 1 and assigned to node 2.
func seedFanoutRoute(t *testing.T) *sql.DB {
	t.Helper()
	db := newPushTestDB(t)
	for _, q := range []string{
		`INSERT INTO users (id, email, password_hash, role) VALUES (1, 'a@b.c', 'x', 'client')`,
		`INSERT INTO clients (id, user_id, display_name) VALUES (1, 1, 'acme')`,
		`INSERT INTO node_groups (id, name, mode) VALUES (1, 'default', 'active_active')`,
		`INSERT INTO plans (id, name, node_group_id, max_domains) VALUES (1, 'basic', 1, 0)`,
		`INSERT INTO services (id, client_id, name, backend_ip, allowed_port_start, allowed_port_end, plan_id, node_group_id)
		 VALUES (1, 1, 'svc', '198.51.100.9', 1, 65535, 1, 1)`,
		`INSERT INTO caddy_nodes (id, name, api_url, public_hostname, node_group_id, max_routes, current_routes,
		   is_enabled, health_status, approved_at)
		 VALUES (1, 'anchor', 'http://127.0.0.1:1', 'a.example', 1, 100, 1, 1, 'healthy', CURRENT_TIMESTAMP),
		        (2, 'peer', 'http://127.0.0.1:1', 'b.example', 1, 100, 1, 1, 'healthy', CURRENT_TIMESTAMP)`,
		`INSERT INTO routes (id, service_id, caddy_node_id, domain, path_prefix, upstream_port, ssl_enabled, status, domain_verified)
		 VALUES (1, 1, 1, 'app.example.com', '', 8080, 1, 'active', 1)`,
		`INSERT INTO route_node_assignments (route_id, node_id) VALUES (1, 2)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	return db
}

func quietService(db *sql.DB) *Service {
	// Long debounce: tests assert on the desired generation, not network traffic.
	return &Service{DB: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), PushDebounceMs: 60000}
}

// A wildcard route served only through a fan-out assignment still needs its
// DNS-01 policy on that peer, or the peer can never issue/renew the cert.
func TestBuildWildcardPolicies_FanoutPeer(t *testing.T) {
	db := seedFanoutRoute(t)
	if _, err := db.Exec(`INSERT INTO dns_providers (name, provider, api_token_enc) VALUES ('example.com', 'cloudflare', 'enc')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE routes SET wildcard_enabled = 1, wildcard_zone = 'example.com' WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	svc := quietService(db)
	svc.DNS01ModuleAvailable = true
	svc.DecryptSecret = func(string) (string, error) { return "tok", nil }

	for _, node := range []int64{1, 2} {
		if got := svc.buildWildcardPolicies(context.Background(), node); len(got) != 1 {
			t.Errorf("node %d: %d wildcard policies, want 1", node, len(got))
		}
	}
}

// A route update must reach every node serving the route, not just its anchor.
func TestUpdateRoute_PushesFanoutPeers(t *testing.T) {
	svc := quietService(seedFanoutRoute(t))
	port := 8081
	changed, err := svc.UpdateRoute(context.Background(), 0, 1, UpdateInput{UpstreamPort: &port})
	if err != nil || !changed {
		t.Fatalf("UpdateRoute: changed=%v err=%v", changed, err)
	}
	for _, node := range []int64{1, 2} {
		if svc.currentGen(node) == 0 {
			t.Errorf("node %d not scheduled after route update", node)
		}
	}
}

// Fleet- and client-wide pushes must include nodes that host a route only
// through a fan-out assignment.
func TestSchedulePushAllAndClient_IncludeFanoutPeers(t *testing.T) {
	db := seedFanoutRoute(t)
	for name, run := range map[string]func(*Service){
		"all":    func(s *Service) { s.SchedulePushAllNodes(context.Background()) },
		"client": func(s *Service) { s.SchedulePushForClient(context.Background(), 1) },
	} {
		svc := quietService(db)
		run(svc)
		for _, node := range []int64{1, 2} {
			if svc.currentGen(node) == 0 {
				t.Errorf("%s: node %d not scheduled", name, node)
			}
		}
	}
}

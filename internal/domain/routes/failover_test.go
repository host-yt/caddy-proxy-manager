package routes

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// recordingNode is a fake Caddy admin API that records the hosts of every
// config it is asked to load.
type recordingNode struct {
	mu    sync.Mutex
	loads [][]string
	srv   *httptest.Server
}

func newRecordingNode(t *testing.T) *recordingNode {
	t.Helper()
	n := &recordingNode{}
	n.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/load" {
			body, _ := io.ReadAll(r.Body)
			n.mu.Lock()
			n.loads = append(n.loads, hostsInConfig(string(body)))
			n.mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(n.srv.Close)
	return n
}

func (n *recordingNode) lastLoad() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.loads) == 0 {
		return nil
	}
	return n.loads[len(n.loads)-1]
}

// TestAutoFailover_MovesRoutesOffADownNode is the edge-failover drill: a node
// that has been down past the grace window must hand its routes to a healthy
// peer in the same group, and that peer must actually be pushed the config -
// moving the row without a push would leave the site down.
func TestAutoFailover_MovesRoutesOffADownNode(t *testing.T) {
	db := newPushTestDB(t)
	ctx := context.Background()
	healthy := newRecordingNode(t)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	exec(`INSERT INTO users (id, email, password_hash, role) VALUES (1, 'a@b.c', 'x', 'client')`)
	exec(`INSERT INTO clients (id, user_id, display_name) VALUES (1, 1, 'acme')`)
	exec(`INSERT INTO node_groups (id, name, mode) VALUES (1, 'default', 'failover')`)
	exec(`INSERT INTO plans (id, name, node_group_id, max_domains) VALUES (1, 'basic', 1, 0)`)
	exec(`INSERT INTO services (id, client_id, name, backend_ip, allowed_port_start, allowed_port_end, plan_id, node_group_id)
	      VALUES (1, 1, 'svc', '10.9.9.9', 1, 65535, 1, 1)`)
	// Node 1 went down 30 minutes ago (past the 5-minute grace window).
	exec(`INSERT INTO caddy_nodes (id, name, api_url, public_hostname, node_group_id, max_routes, current_routes,
	        is_enabled, health_status, last_seen_at, approved_at)
	      VALUES (1, 'edge-down', 'http://127.0.0.1:1', 'down.example', 1, 100, 2, 1, 'down',
	              datetime('now', '-30 minutes'), CURRENT_TIMESTAMP)`)
	exec(`INSERT INTO caddy_nodes (id, name, api_url, public_hostname, node_group_id, max_routes, current_routes,
	        is_enabled, health_status, last_seen_at, approved_at)
	      VALUES (2, 'edge-ok', ?, 'ok.example', 1, 100, 0, 1, 'healthy', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		healthy.srv.URL)
	exec(`INSERT INTO routes (id, service_id, caddy_node_id, domain, path_prefix, upstream_port, ssl_enabled, status, domain_verified)
	      VALUES (1, 1, 1, 'shop.example', '', 8080, 0, 'active', 1)`)
	exec(`INSERT INTO routes (id, service_id, caddy_node_id, domain, path_prefix, upstream_port, ssl_enabled, status, domain_verified)
	      VALUES (2, 1, 1, 'blog.example', '', 8081, 0, 'active', 1)`)

	svc := &Service{DB: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	svc.AutoFailover(ctx)

	var onHealthy int
	if err := db.QueryRow("SELECT COUNT(*) FROM routes WHERE caddy_node_id = 2").Scan(&onHealthy); err != nil {
		t.Fatalf("count moved routes: %v", err)
	}
	if onHealthy != 2 {
		t.Fatalf("%d of 2 routes moved to the healthy node", onHealthy)
	}

	last := healthy.lastLoad()
	if last == nil {
		t.Fatal("healthy node was never pushed a config after the failover")
	}
	for _, want := range []string{"shop.example", "blog.example"} {
		if !contains(last, want) {
			t.Errorf("%s missing from the config pushed to the healthy node: %v", want, last)
		}
	}

	// Counters follow the move, so capacity stays truthful afterwards.
	var downCount, okCount int
	if err := db.QueryRow("SELECT current_routes FROM caddy_nodes WHERE id = 1").Scan(&downCount); err != nil {
		t.Fatalf("read down node: %v", err)
	}
	if err := db.QueryRow("SELECT current_routes FROM caddy_nodes WHERE id = 2").Scan(&okCount); err != nil {
		t.Fatalf("read healthy node: %v", err)
	}
	if downCount != 0 || okCount != 2 {
		t.Errorf("current_routes after failover: down=%d healthy=%d, want 0 and 2", downCount, okCount)
	}
}

// A tunneled route cannot follow (its wg interface lives on the dead node), so
// it must stay put and be surfaced rather than silently moved to a node where
// the backend is unreachable.
func TestAutoFailover_LeavesTunneledRoutesInPlace(t *testing.T) {
	db := newPushTestDB(t)
	ctx := context.Background()
	healthy := newRecordingNode(t)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	exec(`INSERT INTO users (id, email, password_hash, role) VALUES (1, 'a@b.c', 'x', 'client')`)
	exec(`INSERT INTO clients (id, user_id, display_name) VALUES (1, 1, 'acme')`)
	exec(`INSERT INTO node_groups (id, name, mode) VALUES (1, 'default', 'failover')`)
	exec(`INSERT INTO plans (id, name, node_group_id, max_domains) VALUES (1, 'basic', 1, 0)`)
	exec(`INSERT INTO services (id, client_id, name, backend_ip, allowed_port_start, allowed_port_end, plan_id, node_group_id)
	      VALUES (1, 1, 'svc', '10.9.9.9', 1, 65535, 1, 1)`)
	exec(`INSERT INTO caddy_nodes (id, name, api_url, public_hostname, node_group_id, max_routes, current_routes,
	        is_enabled, health_status, last_seen_at, approved_at)
	      VALUES (1, 'edge-down', 'http://127.0.0.1:1', 'down.example', 1, 100, 1, 1, 'down',
	              datetime('now', '-30 minutes'), CURRENT_TIMESTAMP)`)
	exec(`INSERT INTO caddy_nodes (id, name, api_url, public_hostname, node_group_id, max_routes, current_routes,
	        is_enabled, health_status, last_seen_at, approved_at)
	      VALUES (2, 'edge-ok', ?, 'ok.example', 1, 100, 0, 1, 'healthy', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		healthy.srv.URL)
	exec(`INSERT INTO customer_wg_peer (id, client_id, node_id, name, assigned_ip, status)
	      VALUES (1, 1, 1, 'peer1', '10.77.0.5', 'active')`)
	exec(`INSERT INTO routes (id, service_id, caddy_node_id, domain, path_prefix, upstream_port, ssl_enabled,
	        status, domain_verified, via_wg_peer_id)
	      VALUES (1, 1, 1, 'tunnel.example', '', 8080, 0, 'active', 1, 1)`)

	svc := &Service{DB: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	svc.AutoFailover(ctx)

	var nodeID int64
	if err := db.QueryRow("SELECT caddy_node_id FROM routes WHERE id = 1").Scan(&nodeID); err != nil {
		t.Fatalf("read route: %v", err)
	}
	if nodeID != 1 {
		t.Errorf("tunneled route moved to node %d; its WG interface only exists on node 1", nodeID)
	}
}

package routes

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
)

// seedCapacityFixture builds one node group with a single node capped at
// maxRoutes, plus the service/plan a create needs.
func seedCapacityFixture(t *testing.T, db *sql.DB, maxRoutes int) int64 {
	t.Helper()
	exec := func(q string, args ...any) sql.Result {
		t.Helper()
		res, err := db.Exec(q, args...)
		if err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
		return res
	}
	exec(`INSERT INTO users (id, email, password_hash, role) VALUES (1, 'a@b.c', 'x', 'client')`)
	exec(`INSERT INTO clients (id, user_id, display_name) VALUES (1, 1, 'acme')`)
	exec(`INSERT INTO node_groups (id, name, mode) VALUES (1, 'default', 'single')`)
	// max_domains 0 = unlimited, so the plan limit is not what caps this test.
	exec(`INSERT INTO plans (id, name, node_group_id, max_domains, ssl_enabled, websocket_enabled)
	      VALUES (1, 'basic', 1, 0, 1, 1)`)
	exec(`INSERT INTO services (id, client_id, name, backend_ip, allowed_port_start, allowed_port_end, plan_id, node_group_id)
	      VALUES (1, 1, 'svc', '10.9.9.9', 10000, 20000, 1, 1)`)
	res := exec(`INSERT INTO caddy_nodes (name, api_url, public_hostname, node_group_id, max_routes, current_routes,
	               is_enabled, health_status, approved_at)
	             VALUES ('edge1', 'http://127.0.0.1:1', 'edge1.example', 1, ?, 0, 1, 'healthy', CURRENT_TIMESTAMP)`,
		maxRoutes)
	nodeID, _ := res.LastInsertId()
	return nodeID
}

// TestCreate_ConcurrentCreatesRespectMaxRoutes is the placement race
// regression: capacity used to be read (current_routes < max_routes) and then
// incremented in two steps, so concurrent creates could hand out the same last
// free slot and push a node past its max_routes.
func TestCreate_ConcurrentCreatesRespectMaxRoutes(t *testing.T) {
	db := newPushTestDB(t)
	const (
		maxRoutes = 10
		attempts  = 40
	)
	nodeID := seedCapacityFixture(t, db, maxRoutes)

	// A cancelled background context keeps the post-commit advanceRoute
	// goroutines (DNS probe + Caddy push) from doing work after the test.
	bg, cancelBG := context.WithCancel(context.Background())
	cancelBG()
	svc := &Service{DB: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), BgCtx: bg}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		ok       int
		capacity int
		other    []error
	)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := svc.Create(context.Background(), 0, CreateInput{
				ServiceID:    1,
				UpstreamPort: 10001 + i,
				Domain:       fmt.Sprintf("r%d.example", i),
				SSL:          false,
			})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrNodeAtCapacity), errors.Is(err, ErrNoNodeFound), errors.Is(err, sql.ErrNoRows):
				capacity++
			default:
				other = append(other, err)
			}
		}(i)
	}
	wg.Wait()

	var current, max, routeCount int
	if err := db.QueryRow("SELECT current_routes, max_routes FROM caddy_nodes WHERE id = ?", nodeID).
		Scan(&current, &max); err != nil {
		t.Fatalf("read node: %v", err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM routes WHERE caddy_node_id = ?", nodeID).Scan(&routeCount); err != nil {
		t.Fatalf("count routes: %v", err)
	}

	if current > max {
		t.Errorf("node oversubscribed: current_routes = %d, max_routes = %d", current, max)
	}
	if routeCount > maxRoutes {
		t.Errorf("%d routes placed on a node capped at %d", routeCount, maxRoutes)
	}
	if ok != maxRoutes || routeCount != maxRoutes {
		t.Errorf("successes = %d, routes = %d; want exactly %d (capacity refusals: %d, other errors: %v)",
			ok, routeCount, maxRoutes, capacity, other)
	}
}

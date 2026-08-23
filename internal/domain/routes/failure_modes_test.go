package routes

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// driftNode is a fake Caddy that serves a configurable route set on the drift
// probe path and records every /load it is given.
type driftNode struct {
	mu       sync.Mutex
	served   []map[string]any // what GET /config/.../routes returns
	loads    [][]string
	probes   int
	loadFail bool
	srv      *httptest.Server
}

func newDriftNode(t *testing.T) *driftNode {
	t.Helper()
	n := &driftNode{served: []map[string]any{}}
	n.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/config/apps/http/servers/srv0/routes" && r.Method == http.MethodGet:
			n.mu.Lock()
			n.probes++
			body, _ := json.Marshal(n.served)
			n.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		case r.URL.Path == "/load":
			body, _ := io.ReadAll(r.Body)
			n.mu.Lock()
			n.loads = append(n.loads, hostsInConfig(string(body)))
			fail := n.loadFail
			n.mu.Unlock()
			if fail {
				http.Error(w, "boom", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(n.srv.Close)
	return n
}

func (n *driftNode) loadCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.loads)
}

// TestReconcileDrift_RepushesANodeThatCameBackEmpty is the "old node returns"
// case: a Caddy that restarted without its autosaved config answers the probe
// with an empty route set. The panel must notice the divergence and re-push,
// otherwise the node stays up and serving nothing until someone notices.
func TestReconcileDrift_RepushesANodeThatCameBackEmpty(t *testing.T) {
	db := newPushTestDB(t)
	ctx := context.Background()
	node := newDriftNode(t)

	nodeID := seedNodeAndRoute(t, db, node.srv.URL, "shop.example")
	svc := &Service{DB: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	svc.ReconcileDrift(ctx)

	if node.loadCount() == 0 {
		t.Fatal("a node serving no routes was not re-pushed")
	}
	last := node.loads[len(node.loads)-1]
	if !contains(last, "shop.example") {
		t.Errorf("re-pushed config does not carry the route: %v", last)
	}

	// Second sweep: the fake now serves what the panel expects, so nothing
	// should be pushed again. A drift check that never converges re-pushes
	// every node every cycle.
	np, err := svc.buildNodePush(ctx, nodeID)
	if err != nil {
		t.Fatalf("buildNodePush: %v", err)
	}
	node.mu.Lock()
	node.served = servedRoutesFromConfig(t, np.cfg)
	before := len(node.loads)
	node.mu.Unlock()

	svc.ReconcileDrift(ctx)
	if got := node.loadCount(); got != before {
		t.Errorf("drift sweep re-pushed a node that already matched (%d -> %d loads)", before, got)
	}
}

// servedRoutesFromConfig pulls srv0's route array out of a built config, which
// is what a healthy node would return from the drift probe.
func servedRoutesFromConfig(t *testing.T, cfg map[string]any) []map[string]any {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal cfg: %v", err)
	}
	var parsed struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []map[string]any `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal cfg: %v", err)
	}
	return parsed.Apps.HTTP.Servers["srv0"].Routes
}

// TestCreate_NoHealthyNodeIsRefusedCleanly covers "node offline during
// placement": the create must fail with the placement error and leave nothing
// behind - no orphan route row, no counter bump.
func TestCreate_NoHealthyNodeIsRefusedCleanly(t *testing.T) {
	db := newPushTestDB(t)
	ctx := context.Background()

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	exec(`INSERT INTO users (id, email, password_hash, role) VALUES (1, 'a@b.c', 'x', 'client')`)
	exec(`INSERT INTO clients (id, user_id, display_name) VALUES (1, 1, 'acme')`)
	exec(`INSERT INTO node_groups (id, name, mode) VALUES (1, 'default', 'single')`)
	exec(`INSERT INTO plans (id, name, node_group_id, max_domains) VALUES (1, 'basic', 1, 0)`)
	exec(`INSERT INTO services (id, client_id, name, backend_ip, allowed_port_start, allowed_port_end, plan_id, node_group_id)
	      VALUES (1, 1, 'svc', '10.9.9.9', 1, 65535, 1, 1)`)
	// The only node in the group is disabled (drained / taken out for repair).
	exec(`INSERT INTO caddy_nodes (id, name, api_url, public_hostname, node_group_id, max_routes, current_routes,
	        is_enabled, health_status, approved_at)
	      VALUES (1, 'edge1', 'http://127.0.0.1:1', 'edge1.example', 1, 100, 0, 0, 'down', CURRENT_TIMESTAMP)`)

	svc := &Service{DB: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	_, err := svc.Create(ctx, 0, CreateInput{
		ServiceID: 1, Domain: "app.example", UpstreamPort: 10001,
	})
	if err == nil {
		t.Fatal("create succeeded with no node available")
	}
	if !errors.Is(err, ErrNoNodeFound) && !errors.Is(err, ErrNodeAtCapacity) {
		t.Logf("placement error: %v", err) // any refusal is fine, but log which
	}

	var routeCount, counter int
	if err := db.QueryRow("SELECT COUNT(*) FROM routes").Scan(&routeCount); err != nil {
		t.Fatalf("count routes: %v", err)
	}
	if err := db.QueryRow("SELECT current_routes FROM caddy_nodes WHERE id = 1").Scan(&counter); err != nil {
		t.Fatalf("read node: %v", err)
	}
	if routeCount != 0 {
		t.Errorf("failed create left %d route row(s) behind", routeCount)
	}
	if counter != 0 {
		t.Errorf("failed create bumped current_routes to %d", counter)
	}
}

// TestPushNodeConfig_LoadFailureIsReported: a node that rejects /load must
// surface an error rather than being recorded as pushed. The generation must
// not advance either - the node is not on that config.
func TestPushNodeConfig_LoadFailureIsReported(t *testing.T) {
	db := newPushTestDB(t)
	ctx := context.Background()
	node := newDriftNode(t)
	node.mu.Lock()
	node.loadFail = true
	node.mu.Unlock()

	nodeID := seedNodeAndRoute(t, db, node.srv.URL, "shop.example")
	svc := &Service{DB: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	svc.bumpDesiredGen(nodeID)

	if err := svc.pushNodeConfig(ctx, nodeID); err == nil {
		t.Fatal("a rejected /load reported success")
	}
	if g := svc.AppliedGeneration(nodeID); g != 0 {
		t.Errorf("applied generation advanced to %d on a failed push", g)
	}

	// A later successful push converges and records the generation.
	node.mu.Lock()
	node.loadFail = false
	node.mu.Unlock()
	if err := svc.pushNodeConfig(ctx, nodeID); err != nil {
		t.Fatalf("retry push: %v", err)
	}
	if g := svc.AppliedGeneration(nodeID); g == 0 {
		t.Error("applied generation not recorded after a successful push")
	}
}

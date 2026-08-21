package routes

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	proxygateway "github.com/host-yt/caddy-proxy-manager"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// newPushTestDB brings up a real migrated SQLite schema, the same path a
// db_driver=sqlite install takes, so the config build runs its actual queries.
func newPushTestDB(t *testing.T) *sql.DB {
	t.Helper()
	prev := store.Driver()
	store.SetDriver("sqlite3")
	t.Cleanup(func() { store.SetDriver(prev) })

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	dsn := filepath.Join(t.TempDir(), "hpg.db")
	db, err := store.Open(ctx, "sqlite3", dsn, 10*time.Second)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.RunMigrations(ctx, db, proxygateway.MigrationsFS, "migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	return db
}

// TestPushNodeConfig_NoStaleSnapshotOverwrite is the regression for the push
// race: the config used to be built before the per-node lock was taken, so a
// push that blocked on the lock could afterwards /load a snapshot older than
// the state another writer had already pushed, silently reverting it.
//
// The fake node holds the first /load open. While it is held, a second route is
// committed and the node marked dirty - exactly the window that used to lose
// the newer state. The push must not finish on the stale snapshot.
func TestPushNodeConfig_NoStaleSnapshotOverwrite(t *testing.T) {
	db := newPushTestDB(t)
	ctx := context.Background()

	var (
		mu       sync.Mutex
		loads    [][]string // hosts seen in each /load, in order
		firstHit = make(chan struct{})
		release  = make(chan struct{})
		hits     int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/load" {
			w.WriteHeader(http.StatusOK)
			return
		}
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		hits++
		n := hits
		loads = append(loads, hostsInConfig(string(body)))
		mu.Unlock()
		if n == 1 {
			close(firstHit)
			<-release // hold the first load open across the racing commit
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	nodeID := seedNodeAndRoute(t, db, srv.URL, "first.example")

	svc := &Service{DB: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	svc.bumpDesiredGen(nodeID) // the push that is about to run

	done := make(chan error, 1)
	go func() { done <- svc.pushNodeConfig(ctx, nodeID) }()

	<-firstHit
	// Newer state lands while the first /load is still in flight.
	addRoute(t, db, nodeID, "second.example")
	svc.bumpDesiredGen(nodeID)
	close(release)

	if err := <-done; err != nil {
		t.Fatalf("pushNodeConfig: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(loads) < 2 {
		t.Fatalf("only %d /load call(s); the newer generation was never pushed: %v", len(loads), loads)
	}
	last := loads[len(loads)-1]
	if !contains(last, "second.example") {
		t.Errorf("node left without the newer route; last /load hosts = %v", last)
	}
	if !contains(last, "first.example") {
		t.Errorf("node lost the original route; last /load hosts = %v", last)
	}
}

// TestPushGenerations tracks the desired/applied bookkeeping itself.
func TestPushGenerations(t *testing.T) {
	s := &Service{}
	if g := s.currentGen(1); g != 0 {
		t.Fatalf("fresh node generation = %d, want 0", g)
	}
	if g := s.bumpDesiredGen(1); g != 1 {
		t.Fatalf("first bump = %d, want 1", g)
	}
	s.bumpDesiredGen(1)
	if g := s.currentGen(1); g != 2 {
		t.Fatalf("generation = %d, want 2", g)
	}
	if s.currentGen(2) != 0 {
		t.Error("generations must be per node")
	}
	s.recordApplied(1, 2)
	s.recordApplied(1, 1) // an older push must never move applied backwards
	if g := s.AppliedGeneration(1); g != 2 {
		t.Fatalf("applied = %d, want 2", g)
	}
}

// seedNodeAndRoute creates the minimum object graph a config build walks:
// user -> client -> plan/group -> service -> node -> one active route.
func seedNodeAndRoute(t *testing.T, db *sql.DB, apiURL, domain string) int64 {
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
	exec(`INSERT INTO plans (id, name, node_group_id) VALUES (1, 'basic', 1)`)
	exec(`INSERT INTO services (id, client_id, name, backend_ip, allowed_port_start, allowed_port_end, plan_id, node_group_id)
	      VALUES (1, 1, 'svc', '10.9.9.9', 1, 65535, 1, 1)`)
	res := exec(`INSERT INTO caddy_nodes (name, api_url, public_hostname, node_group_id, is_enabled, health_status)
	             VALUES ('edge1', ?, 'edge1.example', 1, 1, 'healthy')`, apiURL)
	nodeID, _ := res.LastInsertId()
	addRoute(t, db, nodeID, domain)
	return nodeID
}

func addRoute(t *testing.T, db *sql.DB, nodeID int64, domain string) {
	t.Helper()
	if _, err := db.Exec(
		`INSERT INTO routes (service_id, caddy_node_id, domain, path_prefix, upstream_port, ssl_enabled, status, domain_verified)
		 VALUES (1, ?, ?, '', 8080, 0, 'active', 1)`, nodeID, domain); err != nil {
		t.Fatalf("insert route %s: %v", domain, err)
	}
}

// hostsInConfig pulls every host matcher value out of a Caddy /load body.
func hostsInConfig(body string) []string {
	var cfg any
	if err := json.Unmarshal([]byte(body), &cfg); err != nil {
		return nil
	}
	var out []string
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			for k, vv := range t {
				if k == "host" {
					if list, ok := vv.([]any); ok {
						for _, h := range list {
							if s, ok := h.(string); ok {
								out = append(out, s)
							}
						}
					}
					continue
				}
				walk(vv)
			}
		case []any:
			for _, vv := range t {
				walk(vv)
			}
		}
	}
	walk(cfg)
	return out
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

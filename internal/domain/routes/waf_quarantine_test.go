package routes

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// poisonNode is a Caddy that refuses any /load carrying `poison`, the way a
// real node refuses a config Coraza cannot parse: 400, whole config rejected.
type poisonNode struct {
	mu    sync.Mutex
	loads []string
	srv   *httptest.Server
}

func newPoisonNode(t *testing.T) *poisonNode {
	t.Helper()
	n := &poisonNode{}
	n.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/load" {
			_, _ = w.Write([]byte("null"))
			return
		}
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "poison") {
			http.Error(w, `{"error":"directive poison: unknown"}`, http.StatusBadRequest)
			return
		}
		n.mu.Lock()
		n.loads = append(n.loads, string(body))
		n.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(n.srv.Close)
	return n
}

func (n *poisonNode) lastLoad() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.loads) == 0 {
		return ""
	}
	return n.loads[len(n.loads)-1]
}

// HPG-SEC-006: one tenant's custom WAF directives used to take the whole
// node's config down - every other tenant on it lost its config too.
func TestPushNodeConfig_BadWAFDirectivesQuarantineOnlyTheirOwnRoute(t *testing.T) {
	db := newPushTestDB(t)
	ctx := context.Background()
	node := newPoisonNode(t)
	nodeID := seedNodeAndRoute(t, db, node.srv.URL, "good.example")
	addRoute(t, db, nodeID, "bad.example")

	var badID int64
	if err := db.QueryRow(`SELECT id FROM routes WHERE domain = 'bad.example'`).Scan(&badID); err != nil {
		t.Fatalf("read route: %v", err)
	}
	if _, err := db.Exec(`UPDATE routes SET waf_enabled = 1, waf_directives = ? WHERE id = ?`,
		"SecRuleRemoveByTag poison", badID); err != nil {
		t.Fatalf("seed directives: %v", err)
	}

	svc := &Service{DB: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), WAFModuleAvailable: true}
	if err := svc.pushNodeConfig(ctx, nodeID); err != nil {
		t.Fatalf("one bad WAF block must not fail the whole node's push: %v", err)
	}

	live := node.lastLoad()
	if strings.Contains(live, "poison") {
		t.Error("the refused directive reached the node")
	}
	for _, h := range []string{"good.example", "bad.example"} {
		if !strings.Contains(live, h) {
			t.Errorf("%s is missing from the published config: %s", h, live)
		}
	}

	var reason, status string
	if err := db.QueryRow(`SELECT COALESCE(waf_quarantine_reason,''), COALESCE(last_compile_status,'')
	                         FROM routes WHERE id = ?`, badID).Scan(&reason, &status); err != nil {
		t.Fatalf("read quarantine: %v", err)
	}
	if reason == "" {
		t.Error("the quarantine reason was not recorded")
	}
	if status != compileQuarantined {
		t.Errorf("compile status = %q, want %q", status, compileQuarantined)
	}

	// The next push must not repeat the probe dance: the parked directives
	// stay out until they are edited.
	before := len(node.loads)
	if err := svc.pushNodeConfig(ctx, nodeID); err != nil {
		t.Fatalf("second push: %v", err)
	}
	if got := len(node.loads) - before; got != 1 {
		t.Errorf("a quarantined route cost %d loads on the next push, want 1", got)
	}

	// Editing the directives gives them another chance.
	if _, err := db.Exec(`UPDATE routes SET waf_directives = ? WHERE id = ?`,
		"SecRuleRemoveById 942100", badID); err != nil {
		t.Fatalf("edit directives: %v", err)
	}
	if err := svc.pushNodeConfig(ctx, nodeID); err != nil {
		t.Fatalf("third push: %v", err)
	}
	if !strings.Contains(node.lastLoad(), "SecRuleRemoveById 942100") {
		t.Error("edited directives must be retried, not held back by a stale quarantine")
	}
}

// An unreachable or otherwise broken node must still fail loudly: only a
// config rejection may be blamed on a route.
func TestPushNodeConfig_NonWAFFailureStillFails(t *testing.T) {
	db := newPushTestDB(t)
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/load" {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("null"))
	}))
	defer srv.Close()
	nodeID := seedNodeAndRoute(t, db, srv.URL, "good.example")
	if _, err := db.Exec(`UPDATE routes SET waf_enabled = 1, waf_directives = 'SecRuleRemoveById 942100'`); err != nil {
		t.Fatalf("seed directives: %v", err)
	}
	svc := &Service{DB: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), WAFModuleAvailable: true}
	if err := svc.pushNodeConfig(ctx, nodeID); err == nil {
		t.Fatal("a node-side failure that is not a config rejection must surface")
	}
}

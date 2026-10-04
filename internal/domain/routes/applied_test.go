package routes

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestNodeApplyStates_PerNodeTruth: one route served by two nodes, one /load
// accepted and one refused, must report each node separately, not one verdict.
func TestNodeApplyStates_PerNodeTruth(t *testing.T) {
	db := newPushTestDB(t)
	ctx := context.Background()

	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/load" {
			http.Error(w, "loading config: boom", http.StatusBadRequest)
		}
	}))
	defer bad.Close()

	nodeA := seedNodeAndRoute(t, db, ok.URL, "multi.example")
	res, err := db.Exec(`INSERT INTO caddy_nodes (name, api_url, public_hostname, node_group_id, is_enabled, health_status)
	                     VALUES ('edge2', ?, 'edge2.example', 1, 1, 'healthy')`, bad.URL)
	if err != nil {
		t.Fatal(err)
	}
	nodeB, _ := res.LastInsertId()
	var routeID int64
	if err := db.QueryRow(`SELECT id FROM routes WHERE domain='multi.example'`).Scan(&routeID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO route_node_assignments (route_id, node_id) VALUES (?, ?), (?, ?)`,
		routeID, nodeA, routeID, nodeB); err != nil {
		t.Fatal(err)
	}

	svc := &Service{DB: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	// Nothing pushed yet: both nodes unknown, never "applied".
	st, err := svc.NodeApplyStates(ctx, []int64{routeID})
	if err != nil {
		t.Fatal(err)
	}
	if got := statesByNode(st[routeID]); len(got) != 2 || got[nodeA] != ApplyUnknown || got[nodeB] != ApplyUnknown {
		t.Fatalf("before push: %v", got)
	}

	if err := svc.pushNodeConfig(ctx, nodeA); err != nil {
		t.Fatalf("push A: %v", err)
	}
	if err := svc.pushNodeConfig(ctx, nodeB); err == nil {
		t.Fatal("push B: want error")
	}
	st, err = svc.NodeApplyStates(ctx, []int64{routeID})
	if err != nil {
		t.Fatal(err)
	}
	got := statesByNode(st[routeID])
	if got[nodeA] != ApplyApplied || got[nodeB] != ApplyFailed {
		t.Fatalf("after push: %v", got)
	}
	for _, n := range st[routeID] {
		if n.NodeID == nodeA && (n.Hash == "" || n.At.IsZero()) {
			t.Errorf("applied node missing hash/at: %+v", n)
		}
		if n.NodeID == nodeB && n.Error == "" {
			t.Errorf("failed node missing error: %+v", n)
		}
	}

	// A scheduled-but-unrun change on A is pending, not applied.
	svc.bumpDesiredGen(nodeA)
	st, _ = svc.NodeApplyStates(ctx, []int64{routeID})
	if got := statesByNode(st[routeID]); got[nodeA] != ApplyPending {
		t.Fatalf("after bump: %v", got)
	}

	// A later successful load clears the failure.
	if _, err := db.Exec(`UPDATE caddy_nodes SET api_url=? WHERE id=?`, ok.URL, nodeB); err != nil {
		t.Fatal(err)
	}
	if err := svc.pushNodeConfig(ctx, nodeB); err != nil {
		t.Fatalf("push B again: %v", err)
	}
	st, _ = svc.NodeApplyStates(ctx, []int64{routeID})
	if got := statesByNode(st[routeID]); got[nodeB] != ApplyApplied {
		t.Fatalf("after recovery: %v", got)
	}
}

func statesByNode(ns []NodeApply) map[int64]string {
	m := map[int64]string{}
	for _, n := range ns {
		m[n.NodeID] = n.State
	}
	return m
}

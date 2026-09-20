package routes

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"
)

// TestSchedulePushForRouteCoversFanoutNodes proves the scheduler reaches every
// node serving a route, not just its anchor. Node-level config (TLS connection
// policies in particular) is rebuilt per node, so missing a fan-out peer leaves
// it on the previous policy while the panel reports the new one as applied.
// Requires TEST_DB_DSN.
func TestSchedulePushForRouteCoversFanoutNodes(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	ctx := context.Background()

	tag := fmt.Sprintf("fanoutpush_%d", time.Now().UnixNano())
	_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0")
	newNode := func(suffix string) int64 {
		res, err := db.ExecContext(ctx,
			`INSERT INTO caddy_nodes (name, api_url, node_group_id, current_routes)
			 VALUES (?, 'http://10.0.0.9:2019', 9999, 0)`, tag+suffix)
		if err != nil {
			t.Fatalf("insert node: %v", err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	anchor, peerA, peerB := newNode("_anchor"), newNode("_a"), newNode("_b")

	res, err := db.ExecContext(ctx,
		`INSERT INTO routes (service_id, caddy_node_id, domain, upstream_port)
		 VALUES (999999, ?, ?, 8080)`, anchor, tag+".example.test")
	if err != nil {
		t.Fatalf("insert route: %v", err)
	}
	routeID, _ := res.LastInsertId()
	for _, nid := range []int64{peerA, peerB, anchor} { // anchor repeated on purpose
		if _, err := db.ExecContext(ctx,
			`INSERT INTO route_node_assignments (route_id, node_id) VALUES (?, ?)`, routeID, nid); err != nil {
			t.Fatalf("assign node %d: %v", nid, err)
		}
	}
	_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=1")
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, "DELETE FROM route_node_assignments WHERE route_id = ?", routeID)
		_, _ = db.ExecContext(ctx, "DELETE FROM routes WHERE id = ?", routeID)
		for _, nid := range []int64{anchor, peerA, peerB} {
			_, _ = db.ExecContext(ctx, "DELETE FROM caddy_nodes WHERE id = ?", nid)
		}
	})

	// A long debounce keeps the scheduled pushes from firing during the test:
	// we assert on the desired generation, not on network traffic.
	svc := &Service{DB: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), PushDebounceMs: 60000}
	svc.SchedulePushForRoute(ctx, routeID)

	for _, tc := range []struct {
		name string
		id   int64
	}{{"anchor", anchor}, {"fan-out peer A", peerA}, {"fan-out peer B", peerB}} {
		if got := svc.currentGen(tc.id); got != 1 {
			t.Errorf("%s: desired generation = %d, want 1 (anchor must be scheduled once, every peer exactly once)", tc.name, got)
		}
	}
}

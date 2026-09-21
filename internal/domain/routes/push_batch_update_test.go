package routes

import (
	"context"
	"fmt"
	"testing"
)

// TestMarkRoutesPushed_UpdatesEveryChunk is the regression for HPG-021: a full
// push used to issue one ExecContext per route ID in a loop. This seeds more
// routes than pushMetaChunkSize so the batched UPDATE must span more than one
// chunk, and verifies every single route - including ones in the tail chunk -
// actually got the new hash, not just the first pushMetaChunkSize of them.
func TestMarkRoutesPushed_UpdatesEveryChunk(t *testing.T) {
	db := newPushTestDB(t)
	ctx := context.Background()
	nodeID := seedNodeAndRoute(t, db, "http://node.invalid:2019", "chunk0.example")

	const total = pushMetaChunkSize + 3 // force a second, partial chunk
	var firstID int64
	if err := db.QueryRowContext(ctx, "SELECT id FROM routes WHERE domain = ?", "chunk0.example").Scan(&firstID); err != nil {
		t.Fatalf("lookup seeded route: %v", err)
	}
	ids := []int64{firstID}
	for i := 1; i < total; i++ {
		domain := fmt.Sprintf("chunk%d.example", i)
		addRoute(t, db, nodeID, domain)
		var id int64
		if err := db.QueryRowContext(ctx, "SELECT id FROM routes WHERE domain = ?", domain).Scan(&id); err != nil {
			t.Fatalf("lookup seeded route %s: %v", domain, err)
		}
		ids = append(ids, id)
	}
	if len(ids) != total {
		t.Fatalf("seeded %d routes, want %d", len(ids), total)
	}

	if err := (&Service{DB: db}).markRoutesPushed(ctx, ids, "deadbeef"); err != nil {
		t.Fatalf("markRoutesPushed: %v", err)
	}

	var stale int
	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM routes WHERE last_pushed_hash IS NULL OR last_pushed_hash <> 'deadbeef'").
		Scan(&stale); err != nil {
		t.Fatalf("count stale rows: %v", err)
	}
	if stale != 0 {
		t.Fatalf("%d of %d routes were not updated - a chunk boundary was dropped", stale, total)
	}
}

// TestMarkRoutesPushed_PropagatesError is the other half of HPG-021: the old
// loop discarded every ExecContext error (`_, _ = ...`), so a failing update
// was invisible. markRoutesPushed must surface it instead of swallowing it.
func TestMarkRoutesPushed_PropagatesError(t *testing.T) {
	db := newPushTestDB(t)
	nodeID := seedNodeAndRoute(t, db, "http://node.invalid:2019", "err.example")
	_ = nodeID
	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}

	err := (&Service{DB: db}).markRoutesPushed(context.Background(), []int64{1}, "deadbeef")
	if err == nil {
		t.Fatal("markRoutesPushed on a closed DB must return an error, not silently succeed")
	}
}

package routes

import (
	"context"
	"io"
	"log/slog"
	"testing"
)

// TestExpectedNodeHash_DetectsBrandingDrift is the regression for HPG-010:
// reconcile used to hash only buildRoutesForNode's bare route list, built
// without ANY of the shaping buildNodePush applies for the real push (error
// branding, capability flags, TLS/L4 policies). A branding-only change was
// therefore invisible to drift detection even though every push emits it
// (apps/http/servers/srv0/errors). expectedNodeHash must now be sourced from
// the same buildNodePush artifact the push path uses.
func TestExpectedNodeHash_DetectsBrandingDrift(t *testing.T) {
	db := newPushTestDB(t)
	ctx := context.Background()
	nodeID := seedNodeAndRoute(t, db, "http://node.invalid:2019", "brand.example")

	svc := &Service{DB: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	before, err := svc.expectedNodeHash(ctx, nodeID)
	if err != nil {
		t.Fatalf("expectedNodeHash (before): %v", err)
	}

	if _, err := db.Exec(
		"INSERT INTO settings (`key`, value) VALUES ('branding.brand_name', 'Acme')"); err != nil {
		t.Fatalf("seed branding setting: %v", err)
	}

	after, err := svc.expectedNodeHash(ctx, nodeID)
	if err != nil {
		t.Fatalf("expectedNodeHash (after): %v", err)
	}

	if before == after {
		t.Fatal("branding change must change the managed snapshot hash, but it did not")
	}
}

// TestExpectedNodeHash_DetectsLayer4Drift is the other half of HPG-010's named
// scenario ("a TLS or L4 policy drifting on a node is invisible to
// reconcile"): the old hash was built purely from HTTP routes and could never
// reflect apps/layer4 appearing or disappearing.
func TestExpectedNodeHash_DetectsLayer4Drift(t *testing.T) {
	db := newPushTestDB(t)
	ctx := context.Background()
	nodeID := seedNodeAndRoute(t, db, "http://node.invalid:2019", "l4.example")

	if _, err := db.Exec(
		`INSERT INTO stream_routes (service_id, caddy_node_id, protocol, listen_port, upstream_port, status)
		 VALUES (1, ?, 'tcp', 5000, 25, 'active')`, nodeID); err != nil {
		t.Fatalf("seed stream route: %v", err)
	}

	svc := &Service{DB: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	withoutL4, err := svc.expectedNodeHash(ctx, nodeID)
	if err != nil {
		t.Fatalf("expectedNodeHash (module off): %v", err)
	}

	svc.Layer4ModuleAvailable = true
	withL4, err := svc.expectedNodeHash(ctx, nodeID)
	if err != nil {
		t.Fatalf("expectedNodeHash (module on): %v", err)
	}

	if withoutL4 == withL4 {
		t.Fatal("apps/layer4 appearing must change the managed snapshot hash, but it did not")
	}
}

// TestNodeSnapshotManifest_StripsVirtualRoutesWithoutMutatingInput guards the
// stripVirtualRoutes helper both sides of the drift comparison share: it must
// return a filtered copy, never mutate the srv0 map that pushNodeConfig is
// about to /load.
func TestNodeSnapshotManifest_StripsVirtualRoutesWithoutMutatingInput(t *testing.T) {
	srv0 := map[string]any{
		"routes": []any{
			map[string]any{"@id": "route_panel_self"},
			map[string]any{"@id": "route_42"},
		},
		"listen": []any{":443"},
	}
	out := stripVirtualRoutes(srv0)

	origRoutes, _ := srv0["routes"].([]any)
	if len(origRoutes) != 2 {
		t.Fatalf("stripVirtualRoutes mutated its input: len=%d", len(origRoutes))
	}
	filtered, _ := out["routes"].([]any)
	if len(filtered) != 1 {
		t.Fatalf("want 1 route surviving the filter, got %d", len(filtered))
	}
	obj, _ := filtered[0].(map[string]any)
	if obj["@id"] != "route_42" {
		t.Fatalf("unexpected surviving route: %v", obj["@id"])
	}
}

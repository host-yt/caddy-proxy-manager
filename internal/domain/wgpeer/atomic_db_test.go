package wgpeer

import (
	"context"
	"errors"
	"testing"
)

// A node failing mid-group must roll back earlier peers and their addresses.
func TestCreateHARollsBackOnLaterNodeFailure(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	ctx := context.Background()
	clientID := insertTestClient(t, db, ctx)
	good := insertTunnelNode(t, db, ctx, "100.96.44.0/24", 1)
	bad := insertTunnelNode(t, db, ctx, "not-a-cidr", 1)

	if _, _, _, err := newTestSvc(db).CreateHA(ctx, CreateHAInput{ClientID: clientID, NodeIDs: []int64{good, bad}, Name: "ha"}); err == nil {
		t.Fatal("create ha: want error for malformed subnet")
	}
	var peers, next int
	if err := db.QueryRow("SELECT COUNT(*) FROM customer_wg_peer WHERE node_id=?", good).Scan(&peers); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT tunnel_next_octet FROM caddy_nodes WHERE id=?", good).Scan(&next); err != nil {
		t.Fatal(err)
	}
	if peers != 0 || next != 2 {
		t.Fatalf("partial group left behind: peers=%d next_octet=%d", peers, next)
	}
}

// A config build failure must leave the token usable; only success consumes it.
func TestConsumeBootstrapKeepsTokenOnFailure(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	ctx := context.Background()
	clientID := insertTestClient(t, db, ctx)
	nodeID := insertTunnelNode(t, db, ctx, "100.96.45.0/24", 1)
	svc := newTestSvc(db)
	peer, token, err := svc.Create(ctx, CreateInput{ClientID: clientID, NodeID: nodeID, Name: "t"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	good := peerPSK(t, db, peer.ID)
	if _, err := db.Exec("UPDATE customer_wg_peer SET psk_enc='garbage' WHERE id=?", peer.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ConsumeBootstrap(ctx, token); err == nil || errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("broken psk: want build error, got %v", err)
	}
	if _, err := db.Exec("UPDATE customer_wg_peer SET psk_enc=? WHERE id=?", good, peer.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ConsumeBootstrap(ctx, token); err != nil {
		t.Fatalf("retry after fix: %v", err)
	}
	if _, err := svc.ConsumeBootstrap(ctx, token); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("second consume: want ErrTokenInvalid, got %v", err)
	}
}

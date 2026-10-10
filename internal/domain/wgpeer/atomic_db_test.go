package wgpeer

import (
	"context"
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

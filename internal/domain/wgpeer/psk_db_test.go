package wgpeer

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/host-yt/caddy-proxy-manager/internal/wireguard"
)

// plainEnc is a no-op Encryptor: these tests assert on the PSK gate, not on
// the envelope format (covered by internal/installstate).
type plainEnc struct{}

func (plainEnc) Encrypt(s string) (string, error) { return s, nil }
func (plainEnc) Decrypt(s string) (string, error) { return s, nil }

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set - skipping DB-backed test")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("DB not reachable: %v", err)
	}
	return db
}

// insertTunnelNode creates a tunnel-enabled node with the given agent_psk.
func insertTunnelNode(t *testing.T, db *sql.DB, ctx context.Context, subnet string, agentPSK int) int64 {
	t.Helper()
	_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0")
	defer db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=1") //nolint:errcheck
	tag := fmt.Sprintf("testpsk_%d", time.Now().UnixNano())
	res, err := db.ExecContext(ctx,
		`INSERT INTO caddy_nodes (name, api_url, node_group_id, current_routes,
		        tunnel_enabled, tunnel_subnet, tunnel_next_octet, tunnel_endpoint,
		        tunnel_pubkey, tunnel_listen_port, agent_psk)
		 VALUES (?, 'http://10.0.0.9:2019', 9999, 0, 1, ?, 2, 'n.example.com:51820',
		         'PUBNODE', 51820, ?)`, tag, subnet, agentPSK)
	if err != nil {
		t.Fatalf("insert node: %v", err)
	}
	id, _ := res.LastInsertId()
	t.Cleanup(func() {
		_, _ = db.Exec("DELETE FROM customer_wg_bootstrap WHERE peer_id IN (SELECT id FROM customer_wg_peer WHERE node_id = ?)", id)
		_, _ = db.Exec("DELETE FROM customer_wg_peer WHERE node_id = ?", id)
		_, _ = db.Exec("DELETE FROM caddy_nodes WHERE id = ?", id)
	})
	return id
}

// insertTestClient creates a clients row (FK target for customer_wg_peer).
func insertTestClient(t *testing.T, db *sql.DB, ctx context.Context) int64 {
	t.Helper()
	_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0")
	defer db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=1") //nolint:errcheck
	res, err := db.ExecContext(ctx,
		`INSERT INTO clients (user_id, display_name) VALUES (?, 'psk test')`,
		time.Now().UnixNano()%1000000000)
	if err != nil {
		t.Fatalf("insert client: %v", err)
	}
	id, _ := res.LastInsertId()
	t.Cleanup(func() { _, _ = db.Exec("DELETE FROM clients WHERE id = ?", id) })
	return id
}

func newTestSvc(db *sql.DB) *Service {
	return &Service{DB: db, Enc: plainEnc{}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func peerPSK(t *testing.T, db *sql.DB, peerID int64) sql.NullString {
	t.Helper()
	var got sql.NullString
	if err := db.QueryRow("SELECT psk_enc FROM customer_wg_peer WHERE id=?", peerID).Scan(&got); err != nil {
		t.Fatalf("read psk_enc: %v", err)
	}
	return got
}

// An agent that never reported psk_supported must not be handed a PSK.
func TestCreateSkipsPSKWhenAgentUnsupported(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	ctx := context.Background()
	clientID := insertTestClient(t, db, ctx)
	nodeID := insertTunnelNode(t, db, ctx, "100.96.40.0/24", 0)

	peer, _, err := newTestSvc(db).Create(ctx, CreateInput{ClientID: clientID, NodeID: nodeID, Name: "t"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if got := peerPSK(t, db, peer.ID); got.Valid {
		t.Fatalf("psk_enc = %q, want NULL for an agent_psk=0 node", got.String)
	}
}

func TestCreateIssuesPSKWhenAgentSupports(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	ctx := context.Background()
	clientID := insertTestClient(t, db, ctx)
	nodeID := insertTunnelNode(t, db, ctx, "100.96.41.0/24", 1)

	peer, _, err := newTestSvc(db).Create(ctx, CreateInput{ClientID: clientID, NodeID: nodeID, Name: "t"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got := peerPSK(t, db, peer.ID)
	if !got.Valid || !wireguard.ValidPresharedKey(got.String) {
		t.Fatalf("psk_enc = %q, want a valid preshared key", got.String)
	}
}

// One unsupported node poisons the whole HA group: a config with a PSK on some
// nodes and not others is half-broken for the customer.
func TestCreateHAGateIsAllOrNothing(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	ctx := context.Background()
	clientID := insertTestClient(t, db, ctx)
	good := insertTunnelNode(t, db, ctx, "100.96.42.0/24", 1)
	bad := insertTunnelNode(t, db, ctx, "100.96.43.0/24", 0)

	_, peers, _, err := newTestSvc(db).CreateHA(ctx, CreateHAInput{ClientID: clientID, NodeIDs: []int64{good, bad}, Name: "ha"})
	if err != nil {
		t.Fatalf("create ha: %v", err)
	}
	for _, p := range peers {
		if got := peerPSK(t, db, p.ID); got.Valid {
			t.Fatalf("peer on node %d got psk_enc %q, want NULL", p.NodeID, got.String)
		}
	}
}

// Second half of the gate: an old agent must never see a PSK in its pull, even
// when the peer row has one (e.g. the agent was downgraded after provisioning).
func TestPeersForNodeGatesOnAgentPSK(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	ctx := context.Background()
	clientID := insertTestClient(t, db, ctx)
	nodeID := insertTunnelNode(t, db, ctx, "100.96.44.0/24", 1)
	svc := newTestSvc(db)

	if _, _, err := svc.Create(ctx, CreateInput{ClientID: clientID, NodeID: nodeID, Name: "t"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	snap, err := svc.PeersForNode(ctx, nodeID)
	if err != nil {
		t.Fatalf("peers: %v", err)
	}
	if len(snap) != 1 || snap[0].PresharedKey == "" {
		t.Fatalf("supported agent got %+v, want a PSK", snap)
	}

	if _, err := db.ExecContext(ctx, "UPDATE caddy_nodes SET agent_psk=0 WHERE id=?", nodeID); err != nil {
		t.Fatalf("downgrade node: %v", err)
	}
	snap, err = svc.PeersForNode(ctx, nodeID)
	if err != nil {
		t.Fatalf("peers: %v", err)
	}
	if len(snap) != 1 || snap[0].PresharedKey != "" {
		t.Fatalf("unsupported agent got %+v, want no PSK", snap)
	}
}

// Rotation is the migration path for classic peers, and it must keep running
// even when a group node lags: key rotation outranks the PSK.
func TestRotateKeyAddsPSKAndDegradesOnUnsupportedNode(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	ctx := context.Background()
	clientID := insertTestClient(t, db, ctx)
	nodeID := insertTunnelNode(t, db, ctx, "100.96.45.0/24", 0)
	svc := newTestSvc(db)

	peer, _, err := svc.Create(ctx, CreateInput{ClientID: clientID, NodeID: nodeID, Name: "t"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE caddy_nodes SET agent_psk=1 WHERE id=?", nodeID); err != nil {
		t.Fatalf("upgrade node: %v", err)
	}
	if _, err := svc.RotateKey(ctx, peer.ID); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if got := peerPSK(t, db, peer.ID); !got.Valid {
		t.Fatal("rotation did not provision a PSK on an upgraded node")
	}

	// Now pretend the peer is part of a group whose node lost support.
	if _, err := db.ExecContext(ctx,
		"UPDATE customer_wg_peer SET peer_group_id='grp-psk-test' WHERE id=?", peer.ID); err != nil {
		t.Fatalf("set group: %v", err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE caddy_nodes SET agent_psk=0 WHERE id=?", nodeID); err != nil {
		t.Fatalf("downgrade node: %v", err)
	}
	before := peerPubkey(t, db, peer.ID)
	if _, err := svc.RotateKey(ctx, peer.ID); err != nil {
		t.Fatalf("rotate must not fail closed on a lagging node: %v", err)
	}
	if after := peerPubkey(t, db, peer.ID); after == before {
		t.Fatal("rotation skipped: pubkey unchanged")
	}
	if got := peerPSK(t, db, peer.ID); got.Valid {
		t.Fatalf("psk_enc = %q after degraded rotation, want NULL so node and .conf agree", got.String)
	}
	var audits int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_log WHERE action='wg_peer.psk_dropped' AND entity_id=?`,
		fmt.Sprint(peer.ID)).Scan(&audits); err != nil {
		t.Fatalf("read audit_log: %v", err)
	}
	if audits != 1 {
		t.Fatalf("audit rows = %d, want 1", audits)
	}
	_, _ = db.Exec("DELETE FROM audit_log WHERE action='wg_peer.psk_dropped' AND entity_id=?", fmt.Sprint(peer.ID))
}

func peerPubkey(t *testing.T, db *sql.DB, peerID int64) string {
	t.Helper()
	var pk string
	if err := db.QueryRow("SELECT pubkey FROM customer_wg_peer WHERE id=?", peerID).Scan(&pk); err != nil {
		t.Fatalf("read pubkey: %v", err)
	}
	return pk
}

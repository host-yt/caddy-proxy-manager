package nodejoin

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
	"github.com/host-yt/caddy-proxy-manager/internal/wireguard"
)

// openTestDB opens a real DB via TEST_DB_DSN or skips - same pattern as
// internal/httpserver/handlers/client_twofa_confirm_test.go.
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

// newTestService builds a Service wired to a real WG sub-service, seeding the
// one setting Redeem requires (wireguard.endpoint) so EnsureKeypair's own
// generated keypair is usable.
func newTestService(t *testing.T, db *sql.DB) *Service {
	t.Helper()
	mgr, err := installstate.New(t.TempDir(), strings.Repeat("x", 32))
	if err != nil {
		t.Fatalf("installstate.New: %v", err)
	}
	ctx := context.Background()
	if _, err := db.ExecContext(ctx,
		"INSERT INTO settings (`key`, value, is_encrypted) VALUES ('wireguard.endpoint', 'vpn.example.com:51820', 0)"+
			" ON DUPLICATE KEY UPDATE value = VALUES(value)"); err != nil {
		t.Fatalf("seed wireguard.endpoint: %v", err)
	}
	wg := &wireguard.Service{DB: func() *sql.DB { return db }, State: mgr}
	return &Service{DB: func() *sql.DB { return db }, WG: wg}
}

// seedNodeGroupAndToken inserts a fresh node_group + join token and returns
// the group id, the plaintext token, and a cleanup func.
func seedNodeGroupAndToken(t *testing.T, db *sql.DB, svc *Service) (groupID int64, plain string, cleanup func()) {
	t.Helper()
	ctx := context.Background()
	res, err := db.ExecContext(ctx,
		`INSERT INTO node_groups (name) VALUES (?)`, fmt.Sprintf("grp_%d", time.Now().UnixNano()))
	if err != nil {
		t.Fatalf("insert node_group: %v", err)
	}
	groupID, _ = res.LastInsertId()

	tok, err := svc.Mint(ctx, MintOpts{NodeGroupID: groupID, MaxRoutes: 10, Priority: 50})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	cleanup = func() {
		_, _ = db.ExecContext(ctx, "DELETE FROM caddy_nodes WHERE node_group_id = ?", groupID)
		_, _ = db.ExecContext(ctx, "DELETE FROM node_join_tokens WHERE node_group_id = ?", groupID)
		_, _ = db.ExecContext(ctx, "DELETE FROM node_groups WHERE id = ?", groupID)
	}
	return groupID, tok.Plain, cleanup
}

// TestRedeemSecondCallFailsNoOrphanNode: a second Redeem of an already-used
// token must fail, and must leave no caddy_nodes row behind (NODE_WG-05).
func TestRedeemSecondCallFailsNoOrphanNode(t *testing.T) {
	db := openTestDB(t)
	svc := newTestService(t, db)
	_, plain, cleanup := seedNodeGroupAndToken(t, db, svc)
	defer cleanup()

	ctx := context.Background()
	_, _, err := svc.Redeem(ctx, JoinRequest{Token: plain}, "https://ask.example.com", "ops@example.com")
	if err != nil {
		t.Fatalf("first Redeem: %v", err)
	}

	var nodeCountBefore int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM caddy_nodes WHERE node_group_id = (SELECT node_group_id FROM node_join_tokens WHERE token_prefix = ?)",
		plain[len("hpg_join_"):len("hpg_join_")+12]).Scan(&nodeCountBefore); err != nil {
		t.Fatalf("count nodes before: %v", err)
	}
	if nodeCountBefore != 1 {
		t.Fatalf("expected exactly 1 node after first Redeem, got %d", nodeCountBefore)
	}

	_, _, err = svc.Redeem(ctx, JoinRequest{Token: plain}, "https://ask.example.com", "ops@example.com")
	if err == nil {
		t.Fatal("second Redeem of the same token succeeded, want error")
	}

	var nodeCountAfter int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM caddy_nodes WHERE node_group_id = (SELECT node_group_id FROM node_join_tokens WHERE token_prefix = ?)",
		plain[len("hpg_join_"):len("hpg_join_")+12]).Scan(&nodeCountAfter); err != nil {
		t.Fatalf("count nodes after: %v", err)
	}
	if nodeCountAfter != 1 {
		t.Fatalf("second Redeem left the node count at %d, want still 1 (no orphan row)", nodeCountAfter)
	}
}

// TestRedeemConcurrentOnlyOneWins: N concurrent Redeem calls on the SAME
// token must yield exactly one success and exactly one caddy_nodes row -
// this is the TOCTOU race NODE_WG-05 closes (concurrent joins all passing
// the token check, all allocating an IP, all inserting a disabled node).
func TestRedeemConcurrentOnlyOneWins(t *testing.T) {
	db := openTestDB(t)
	svc := newTestService(t, db)
	groupID, plain, cleanup := seedNodeGroupAndToken(t, db, svc)
	defer cleanup()

	const n = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	failures := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := context.Background()
			_, _, err := svc.Redeem(ctx, JoinRequest{Token: plain}, "https://ask.example.com", "ops@example.com")
			mu.Lock()
			if err == nil {
				successes++
			} else {
				failures++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	if successes != 1 {
		t.Fatalf("got %d successful concurrent Redeems, want exactly 1 (failures=%d)", successes, failures)
	}
	if failures != n-1 {
		t.Fatalf("got %d failed concurrent Redeems, want %d", failures, n-1)
	}

	var nodeCount int
	if err := db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM caddy_nodes WHERE node_group_id = ?", groupID).Scan(&nodeCount); err != nil {
		t.Fatalf("count nodes: %v", err)
	}
	if nodeCount != 1 {
		t.Fatalf("concurrent redeems left %d node rows, want exactly 1 (losers must leave no rows behind)", nodeCount)
	}
}

package wireguard

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestWriteSkipsUnchangedContent is what makes the periodic mesh reconcile
// affordable: every replica re-renders wg0.conf on a timer, and the sidecar
// runs `wg syncconf` whenever the file's mtime moves. Rewriting identical
// content would hand it a needless reconfigure every cycle.
func TestWriteSkipsUnchangedContent(t *testing.T) {
	db := openPSKTestDB(t)
	ctx := context.Background()
	grp := seedGroup(t, db)
	res, err := db.ExecContext(ctx,
		`INSERT INTO caddy_nodes (name, api_url, public_hostname, node_group_id, max_routes, priority,
		   is_enabled, health_status, wg_ip, wg_public_key, approved_at)
		 VALUES (?, 'http://10.66.0.9:2019', 'n.example.com', ?, 10, 50, 1, 'unknown', '10.66.0.9', ?, NOW())`,
		"write-test-node", grp, "PeerPubKeyBase64Placeholder000000000000000=")
	if err != nil {
		t.Fatalf("insert node: %v", err)
	}
	id, _ := res.LastInsertId()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), "DELETE FROM caddy_nodes WHERE id = ?", id)
		_, _ = db.ExecContext(context.Background(), "DELETE FROM node_groups WHERE id = ?", grp)
	})

	dir := t.TempDir()
	cw := &ConfigWriter{Dir: dir}
	cp := ControlPlane{
		ListenPort: 51820, Subnet: "10.66.0.0/24", ControlIP: "10.66.0.1",
		PrivateKey: "priv", PublicKey: "pub",
	}
	if err := cw.Write(ctx, db, cp); err != nil {
		t.Fatalf("first write: %v", err)
	}
	target := filepath.Join(dir, "wg0.conf")
	first, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}

	// Coarse filesystem timestamps would hide a rewrite done within the same
	// tick, so put a gap between the two writes.
	time.Sleep(1100 * time.Millisecond)
	if err := cw.Write(ctx, db, cp); err != nil {
		t.Fatalf("second write: %v", err)
	}
	second, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if !second.ModTime().Equal(first.ModTime()) {
		t.Errorf("unchanged config was rewritten (mtime %v -> %v): the sidecar would resync on every reconcile tick",
			first.ModTime(), second.ModTime())
	}

	// A real change must still land.
	if _, err := db.ExecContext(ctx,
		"UPDATE caddy_nodes SET wg_ip = '10.66.0.11' WHERE id = ?", id); err != nil {
		t.Fatal(err)
	}
	if err := cw.Write(ctx, db, cp); err != nil {
		t.Fatalf("third write: %v", err)
	}
	third, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if third.ModTime().Equal(first.ModTime()) {
		t.Error("changed config was not written")
	}
}

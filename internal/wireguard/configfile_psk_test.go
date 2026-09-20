package wireguard

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
)

// renderWithPeer inserts one approved node carrying the given encrypted PSK
// columns and renders wg0.conf for it.
func renderWithPeer(t *testing.T, cw *ConfigWriter, active, pending sql.NullString) (string, error) {
	t.Helper()
	db := openPSKTestDB(t)
	ctx := context.Background()
	grp := seedGroup(t, db)
	res, err := db.ExecContext(ctx,
		`INSERT INTO caddy_nodes (name, api_url, public_hostname, node_group_id, max_routes, priority,
		   is_enabled, health_status, wg_ip, wg_public_key, approved_at, wg_psk_enc, wg_psk_pending_enc)
		 VALUES (?, 'http://10.66.0.9:2019', 'n.example.com', ?, 10, 50, 1, 'unknown', '10.66.0.9', ?, NOW(), ?, ?)`,
		"psk-test-node", grp, "PeerPubKeyBase64Placeholder000000000000000=", active, pending)
	if err != nil {
		t.Fatalf("insert node: %v", err)
	}
	id, _ := res.LastInsertId()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), "DELETE FROM caddy_nodes WHERE id = ?", id)
		_, _ = db.ExecContext(context.Background(), "DELETE FROM node_groups WHERE id = ?", grp)
	})
	return cw.Render(ctx, db, ControlPlane{
		ListenPort: 51820, Subnet: "10.66.0.0/24", ControlIP: "10.66.0.1",
		PrivateKey: "priv", PublicKey: "pub",
	})
}

func newTestEnc(t *testing.T) *installstate.Manager {
	t.Helper()
	m, err := installstate.New(t.TempDir(), strings.Repeat("k", 32))
	if err != nil {
		t.Fatalf("installstate.New: %v", err)
	}
	return m.Scoped("wg")
}

// TestRenderEmitsActivePSKNotPending is the load-bearing one: a staged key
// must never reach the sidecar, or the mesh switches before the node did.
func TestRenderEmitsActivePSKNotPending(t *testing.T) {
	enc := newTestEnc(t)
	activePSK, _ := GeneratePresharedKey()
	pendingPSK, _ := GeneratePresharedKey()
	activeEnc, err := enc.Encrypt(activePSK)
	if err != nil {
		t.Fatal(err)
	}
	pendingEnc, err := enc.Encrypt(pendingPSK)
	if err != nil {
		t.Fatal(err)
	}
	out, err := renderWithPeer(t, &ConfigWriter{Dir: t.TempDir(), Enc: enc},
		sql.NullString{String: activeEnc, Valid: true},
		sql.NullString{String: pendingEnc, Valid: true})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(out, "PresharedKey = "+activePSK) {
		t.Errorf("active PSK missing from rendered config:\n%s", out)
	}
	if strings.Contains(out, pendingPSK) {
		t.Fatalf("PENDING PSK leaked into wg0.conf:\n%s", out)
	}
}

// TestRenderNoPSKColumn: a node without a key renders exactly as before.
func TestRenderNoPSKColumn(t *testing.T) {
	out, err := renderWithPeer(t, &ConfigWriter{Dir: t.TempDir(), Enc: newTestEnc(t)},
		sql.NullString{}, sql.NullString{})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(out, "PresharedKey") {
		t.Fatalf("unexpected PresharedKey line:\n%s", out)
	}
}

// TestRenderDecryptFailureIsFatal: rendering must fail (leaving the last good
// file untouched) rather than silently dropping the key the node already has.
func TestRenderDecryptFailureIsFatal(t *testing.T) {
	_, err := renderWithPeer(t, &ConfigWriter{Dir: t.TempDir(), Enc: newTestEnc(t)},
		sql.NullString{String: "v2:wg:not-valid-ciphertext", Valid: true}, sql.NullString{})
	if err == nil {
		t.Fatal("render succeeded with an undecryptable PSK, want error")
	}
}

// TestRenderNoDecryptorIsFatal: same reasoning when Enc was never wired.
func TestRenderNoDecryptorIsFatal(t *testing.T) {
	enc := newTestEnc(t)
	psk, _ := GeneratePresharedKey()
	ct, err := enc.Encrypt(psk)
	if err != nil {
		t.Fatal(err)
	}
	_, err = renderWithPeer(t, &ConfigWriter{Dir: t.TempDir()},
		sql.NullString{String: ct, Valid: true}, sql.NullString{})
	if err == nil {
		t.Fatal("render succeeded without a decryptor, want error")
	}
}

package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/domain/wgpeer"
)

// plainEnc is a no-op Encryptor - these tests assert on the capability gate,
// not on the envelope format.
type plainEnc struct{}

func (plainEnc) Encrypt(s string) (string, error) { return s, nil }
func (plainEnc) Decrypt(s string) (string, error) { return s, nil }

// testPSKValue is a well-formed WG preshared key (32 bytes, base64).
const testPSKValue = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="

// insertPSKNode creates a node with a known agent token and agent_psk value,
// plus one peer carrying psk_enc. Returns the node id and the bearer token.
func insertPSKNode(t *testing.T, db *sql.DB, agentPSK int) (int64, string) {
	t.Helper()
	ctx := context.Background()
	token := fmt.Sprintf("psktok%d", time.Now().UnixNano())
	_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0")
	res, err := db.ExecContext(ctx,
		`INSERT INTO caddy_nodes (name, api_url, node_group_id, current_routes, agent_token_hash, agent_psk)
		 VALUES (?, 'http://10.0.0.9:2019', 9999, 0, SHA2(?, 256), ?)`,
		token, token, agentPSK)
	if err != nil {
		t.Fatalf("insert node: %v", err)
	}
	nodeID, _ := res.LastInsertId()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO customer_wg_peer (client_id, node_id, name, pubkey, assigned_ip, status, psk_enc)
		 VALUES (1, ?, 'p', 'PUBKEY', '100.96.9.5', 'active', ?)`, nodeID, testPSKValue); err != nil {
		t.Fatalf("insert peer: %v", err)
	}
	_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=1")
	t.Cleanup(func() {
		_, _ = db.Exec("DELETE FROM customer_wg_peer WHERE node_id = ?", nodeID)
		_, _ = db.Exec("DELETE FROM caddy_nodes WHERE id = ?", nodeID)
	})
	return nodeID, token
}

func pskTestHandler(db *sql.DB) *WGBootstrapHandler {
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &WGBootstrapHandler{
		DB:     func() *sql.DB { return db },
		Logger: lg,
		Peers:  &wgpeer.Service{DB: db, Logger: lg, Enc: plainEnc{}},
	}
}

func pullBody(t *testing.T, h *WGBootstrapHandler, token string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/node/wg/peers", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.NodePeersPull(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("pull status %d: %s", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

// An agent that reported psk_supported gets the key; one that never did must
// not see it - an unknown line makes `wg syncconf` drop every peer.
func TestNodePeersPullGatesPresharedKey(t *testing.T) {
	db := openTestDBHandlers(t)
	defer db.Close()
	h := pskTestHandler(db)

	okNode, okToken := insertPSKNode(t, db, 1)
	if body := pullBody(t, h, okToken); !strings.Contains(body, `"preshared_key":"`+testPSKValue+`"`) {
		t.Fatalf("supported agent body = %s, want preshared_key", body)
	}

	_, oldToken := insertPSKNode(t, db, 0)
	if body := pullBody(t, h, oldToken); strings.Contains(body, "preshared_key") {
		t.Fatalf("old agent body = %s, want no preshared_key", body)
	}

	// A stored key that no longer decodes drops the whole peer: serving it
	// PSK-less would just fail the handshake with no signal.
	if _, err := db.Exec("UPDATE customer_wg_peer SET psk_enc='garbage' WHERE node_id=?", okNode); err != nil {
		t.Fatalf("corrupt psk: %v", err)
	}
	if body := pullBody(t, h, okToken); body != `{"peers":[]}` {
		t.Fatalf("peer with unusable PSK body = %s, want no peers", body)
	}
}

// psk_supported flips agent_psk; an agent that omits the field leaves it alone.
func TestNodeStatsPSKSupportedCapability(t *testing.T) {
	db := openTestDBHandlers(t)
	defer db.Close()
	h := pskTestHandler(db)
	nodeID, token := insertPSKNode(t, db, 0)

	post := func(nodeJSON string) {
		t.Helper()
		body, _ := json.Marshal(json.RawMessage(`{"stats":[],"node":` + nodeJSON + `}`))
		req := httptest.NewRequest(http.MethodPost, "/api/node/wg/stats", strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.NodePeerStatsReport(rec, req)
		if rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
			t.Fatalf("stats status %d: %s", rec.Code, rec.Body.String())
		}
	}
	agentPSK := func() int {
		t.Helper()
		var v int
		if err := db.QueryRow("SELECT agent_psk FROM caddy_nodes WHERE id=?", nodeID).Scan(&v); err != nil {
			t.Fatalf("read agent_psk: %v", err)
		}
		return v
	}

	post(`{"ip_forward_enabled":true}`) // old agent: field absent
	if got := agentPSK(); got != 0 {
		t.Fatalf("agent_psk = %d after a report without psk_supported, want 0", got)
	}
	post(`{"ip_forward_enabled":true,"psk_supported":true}`)
	if got := agentPSK(); got != 1 {
		t.Fatalf("agent_psk = %d after psk_supported=true, want 1", got)
	}
	post(`{"ip_forward_enabled":true,"psk_supported":false}`)
	if got := agentPSK(); got != 0 {
		t.Fatalf("agent_psk = %d after psk_supported=false, want 0", got)
	}
}

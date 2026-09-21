package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

// pullRec performs the peer pull the way an agent of the given generation
// would: a current one declares PSK support on the request, a pre-PSK one
// sends no such header.
func pullRec(h *WGBootstrapHandler, token string, declaresPSK bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/node/wg/peers", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if declaresPSK {
		req.Header.Set("X-HPG-Agent-PSK", "1")
	}
	rec := httptest.NewRecorder()
	h.NodePeersPull(rec, req)
	return rec
}

func pullBody(t *testing.T, h *WGBootstrapHandler, token string) string {
	t.Helper()
	rec := pullRec(h, token, true)
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

	// A stored key that no longer decodes drops the whole peer: serving it
	// PSK-less would just fail the handshake with no signal.
	if _, err := db.Exec("UPDATE customer_wg_peer SET psk_enc='garbage' WHERE node_id=?", okNode); err != nil {
		t.Fatalf("corrupt psk: %v", err)
	}
	if body := pullBody(t, h, okToken); body != `{"psk_managed":true,"peers":[]}` {
		t.Fatalf("peer with unusable PSK body = %s, want no peers", body)
	}
}

// An agent upgraded after a rollback pulls with the capability header while
// the stored flag is still 0. The flag must be raised before the peer lookup
// reads it, or the agent gets a keyless peer set and wipes every live key.
func TestNodePeersPullRestoresCapabilityOnUpgrade(t *testing.T) {
	db := openTestDBHandlers(t)
	defer db.Close()
	h := pskTestHandler(db)
	nodeID, token := insertPSKNode(t, db, 0) // rolled back earlier, never reported since

	body := pullBody(t, h, token)
	if !strings.Contains(body, `"preshared_key":"`+testPSKValue+`"`) {
		t.Fatalf("upgraded agent body = %s, want the peer's preshared_key back", body)
	}
	if !strings.Contains(body, `"psk_managed":true`) {
		t.Fatalf("body = %s, want psk_managed so the agent knows omissions are intentional", body)
	}
	var agentPSK int
	if err := db.QueryRow("SELECT agent_psk FROM caddy_nodes WHERE id = ?", nodeID).Scan(&agentPSK); err != nil {
		t.Fatal(err)
	}
	if agentPSK != 1 {
		t.Error("capability declared on the pull was not persisted")
	}
}

// A peer set served without a recorded capability is the bug itself, so a
// failed capability write must produce no peers at all.
func TestNodePeersPullFailsClosedWhenCapabilityWriteFails(t *testing.T) {
	db := openTestDBHandlers(t)
	defer db.Close()
	h := pskTestHandler(db)
	nodeID, token := insertPSKNode(t, db, 0)

	// Hold the node row so the capability UPDATE cannot land: the handler's
	// 3s context expires on it while the reads around it still work.
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var pin int64
	if err := tx.QueryRow("SELECT id FROM caddy_nodes WHERE id = ? FOR UPDATE", nodeID).Scan(&pin); err != nil {
		t.Fatal(err)
	}

	rec := pullRec(h, token, true)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500 - no peer set without a recorded capability", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "peers") {
		t.Errorf("served a peer set anyway: %s", rec.Body.String())
	}
}

// A rolled-back agent must not be handed a peer set it would apply without
// the keys: that single syncconf would drop every PSK-bearing tunnel on the
// node at once. Its current config still works, so the pull is refused and
// the stored capability is corrected on the spot.
func TestNodePeersPullRefusesDowngradedAgentWithPSKPeers(t *testing.T) {
	db := openTestDBHandlers(t)
	defer db.Close()
	h := pskTestHandler(db)
	nodeID, token := insertPSKNode(t, db, 1) // node has one peer carrying a PSK

	rec := pullRec(h, token, false)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409 - serving this agent would strip live PSKs", rec.Code)
	}
	if strings.Contains(rec.Body.String(), testPSKValue) {
		t.Error("refusal body leaked the preshared key")
	}
	var agentPSK int
	if err := db.QueryRow("SELECT agent_psk FROM caddy_nodes WHERE id = ?", nodeID).Scan(&agentPSK); err != nil {
		t.Fatal(err)
	}
	if agentPSK != 0 {
		t.Error("capability still recorded as supported after an agent that does not declare it pulled")
	}
}

// Without PSK-bearing peers there is nothing to protect, so an old agent is
// served normally - a downgraded fleet must not be bricked by the guard.
func TestNodePeersPullServesDowngradedAgentWithoutPSKPeers(t *testing.T) {
	db := openTestDBHandlers(t)
	defer db.Close()
	h := pskTestHandler(db)
	nodeID, token := insertPSKNode(t, db, 1)
	if _, err := db.Exec("UPDATE customer_wg_peer SET psk_enc = NULL WHERE node_id = ?", nodeID); err != nil {
		t.Fatal(err)
	}

	rec := pullRec(h, token, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: no PSK peers means nothing to break", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "preshared_key") {
		t.Error("PSK-less pull still advertised a preshared key")
	}
}

// psk_supported is re-asserted on every report: absent means "not supported",
// so a rollback to a pre-PSK agent clears the flag instead of leaving peers
// with a key the agent ignores. The 1->0 edge is audited.
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

	auditRows := func() int {
		t.Helper()
		var n int
		if err := db.QueryRow(
			`SELECT COUNT(*) FROM audit_log
			  WHERE action='node.psk_capability_lost' AND entity_id=?
			    AND JSON_EXTRACT(meta, '$.psk_peers') = 1`,
			fmt.Sprint(nodeID)).Scan(&n); err != nil {
			t.Fatalf("read audit_log: %v", err)
		}
		return n
	}
	t.Cleanup(func() {
		_, _ = db.Exec("DELETE FROM audit_log WHERE entity_id=? AND action='node.psk_capability_lost'", fmt.Sprint(nodeID))
	})

	post(`{"ip_forward_enabled":true,"psk_supported":true}`)
	if got := agentPSK(); got != 1 {
		t.Fatalf("agent_psk = %d after psk_supported=true, want 1", got)
	}
	// Rolled back to a pre-PSK agent: the field is gone, the flag must follow,
	// and the operator must see how many peers that just broke.
	post(`{"ip_forward_enabled":true}`)
	if got := agentPSK(); got != 0 {
		t.Fatalf("agent_psk = %d after a report without psk_supported, want 0", got)
	}
	if n := auditRows(); n != 1 {
		t.Fatalf("audit rows for the 1->0 edge = %d, want 1 (with psk_peers=1)", n)
	}
	// Steady state at 0: no repeated audit spam.
	post(`{"ip_forward_enabled":true}`)
	if n := auditRows(); n != 1 {
		t.Fatalf("audit rows after a second unsupported report = %d, want 1", n)
	}
	post(`{"ip_forward_enabled":true,"psk_supported":true}`)
	if got := agentPSK(); got != 1 {
		t.Fatalf("agent_psk = %d after psk_supported=true, want 1", got)
	}
	post(`{"ip_forward_enabled":true,"psk_supported":false}`)
	if got := agentPSK(); got != 0 {
		t.Fatalf("agent_psk = %d after psk_supported=false, want 0", got)
	}
	if n := auditRows(); n != 2 {
		t.Fatalf("audit rows after an explicit false = %d, want 2", n)
	}
}

// ---- deterministic interleavings (SQLite + statement hook) ---------------
//
// The MySQL-backed tests above cover the steady states. The two below pin an
// exact statement order, which needs the hook driver from
// admin_hosts_mtls_tls_test.go rather than a timing race.

// pskHookDB is the migrated SQLite fixture with node 1 turned into a tunnel
// node the agent can authenticate to, plus one active peer carrying a PSK.
func pskHookDB(t *testing.T, agentPSK int) (*sql.DB, string) {
	t.Helper()
	db := mtlsTLSEditDB(t)
	const token = "hook-node-token"
	for _, s := range []string{
		`UPDATE caddy_nodes SET agent_token_hash = SHA2('` + token + `', 256), agent_psk = ` + fmt.Sprint(agentPSK) + ` WHERE id = 1`,
		`INSERT INTO customer_wg_peer (client_id, node_id, name, pubkey, assigned_ip, status, psk_enc)
		   VALUES (1, 1, 'p', 'PUBKEY', '100.96.9.5', 'active', '` + testPSKValue + `')`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("seed %q: %v", s, err)
		}
	}
	return db, token
}

// The window round 4 found: the pull has recorded "supports PSK" and is
// about to read the peers when a stats report from an older agent lands and
// clears the stored flag. The response must not claim to be the
// authoritative key set while carrying no keys - the agent would then wipe
// every live key on the node. Keys and claim have to come from one decision.
func TestNodePeersPull_CapabilityFlippedBetweenWriteAndPeerQuery(t *testing.T) {
	db, token := pskHookDB(t, 0)
	h := pskTestHandler(db)
	var once sync.Once
	setMTLSSQLHook(t, func(exec func(string) error, query string) error {
		if strings.HasPrefix(query, "SELECT p.pubkey") {
			once.Do(func() {
				// What NodePeerStatsReport does for a report without psk_supported.
				if err := exec("UPDATE caddy_nodes SET agent_psk = 0 WHERE id = 1"); err != nil {
					t.Errorf("interleaved stats report failed: %v", err)
				}
			})
		}
		return nil
	})

	rec := pullRec(h, token, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	managed := strings.Contains(body, `"psk_managed":true`)
	keyed := strings.Contains(body, `"preshared_key":"`+testPSKValue+`"`)
	if managed != keyed {
		t.Fatalf("snapshot is self-contradictory (psk_managed=%v, carries key=%v): %s", managed, keyed, body)
	}
	if !managed {
		t.Fatalf("agent declared PSK support and must be served the keys: %s", body)
	}
}

// The downgrade branch asks how many peers would lose their key. A failed
// count is not "none": serving a pre-PSK agent on that answer is the exact
// syncconf that drops every such tunnel.
func TestNodePeersPull_RefusesWhenPSKPeerCountFails(t *testing.T) {
	db, token := pskHookDB(t, 1)
	h := pskTestHandler(db)
	setMTLSSQLHook(t, func(_ func(string) error, query string) error {
		if strings.HasPrefix(query, "SELECT COUNT(*) FROM customer_wg_peer WHERE node_id") {
			return errors.New("injected count failure")
		}
		return nil
	})

	rec := pullRec(h, token, false)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"peers"`) {
		t.Errorf("served a peer set on a failed count: %s", rec.Body.String())
	}
}

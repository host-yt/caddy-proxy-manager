package handlers

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
	"github.com/host-yt/caddy-proxy-manager/internal/wireguard"
)

// seedPSKNode inserts a node with a staged PSK + rekey token and returns the
// node id and the plaintext token.
func seedPSKNode(t *testing.T, db *sql.DB, enc *installstate.Manager, activePSK string, expiresExpr string) (int64, string) {
	t.Helper()
	ctx := context.Background()
	res, err := db.ExecContext(ctx, "INSERT INTO node_groups (name) VALUES (?)",
		fmt.Sprintf("pskh_%d", time.Now().UnixNano()))
	if err != nil {
		t.Fatalf("insert node_group: %v", err)
	}
	grp, _ := res.LastInsertId()

	pending, _ := wireguard.GeneratePresharedKey()
	pendingEnc, err := enc.Encrypt(pending)
	if err != nil {
		t.Fatal(err)
	}
	token := hex.EncodeToString([]byte(fmt.Sprintf("%032d", time.Now().UnixNano()%1e16)))
	sum := sha256.Sum256([]byte(token))
	tokenEnc, err := enc.Encrypt(token)
	if err != nil {
		t.Fatal(err)
	}
	var activeEnc sql.NullString
	if activePSK != "" {
		ct, cerr := enc.Encrypt(activePSK)
		if cerr != nil {
			t.Fatal(cerr)
		}
		activeEnc = sql.NullString{String: ct, Valid: true}
	}
	// wg_ip and wg_public_key are unique; derive both from the group id so
	// several seeded nodes can coexist inside one test.
	wgIP := fmt.Sprintf("10.77.%d.%d", (grp/250)%250, grp%250)
	pubKey := fmt.Sprintf("PeerPubKeyBase64Placeholder%015d=", grp)
	res, err = db.ExecContext(ctx,
		`INSERT INTO caddy_nodes (name, api_url, public_hostname, node_group_id, max_routes, priority,
		   is_enabled, health_status, wg_ip, wg_public_key, approved_at,
		   wg_psk_enc, wg_psk_pending_enc, wg_psk_token_hash, wg_psk_token_enc, wg_psk_token_expires)
		 VALUES (?, 'http://10.77.0.1:2019', 'p.example.com', ?, 10, 50, 1, 'unknown', ?, ?, NOW(),
		   ?, ?, ?, ?, `+expiresExpr+`)`,
		fmt.Sprintf("pskh-node-%d", time.Now().UnixNano()), grp, wgIP, pubKey,
		activeEnc, pendingEnc, hex.EncodeToString(sum[:]), tokenEnc)
	if err != nil {
		t.Fatalf("insert node: %v", err)
	}
	id, _ := res.LastInsertId()
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = db.ExecContext(bg, "DELETE FROM caddy_nodes WHERE id = ?", id)
		_, _ = db.ExecContext(bg, "DELETE FROM node_groups WHERE id = ?", grp)
	})
	return id, token
}

const testManagerPubKey = "ManagerPubKeyBase64Placeholder00000000000a="

func newPSKHandler(t *testing.T, db *sql.DB, enc *installstate.Manager, write func(context.Context) error) *NodePSKHandler {
	t.Helper()
	return &NodePSKHandler{
		DB:            func() *sql.DB { return db },
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Enc:           enc,
		WriteWGConfig: write,
		PeerPublicKey: func(context.Context) (string, error) { return testManagerPubKey, nil },
	}
}

// pskGet builds the bearer-authenticated fetch request. The token moved out
// of the query string so it stays out of proxy logs and /proc.
func pskGet(token string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/node/psk", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func pskConfirmReq(token string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/node/psk/confirm", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func pskTestEnc(t *testing.T) *installstate.Manager {
	t.Helper()
	m, err := installstate.New(t.TempDir(), strings.Repeat("z", 32))
	if err != nil {
		t.Fatalf("installstate.New: %v", err)
	}
	return m.Scoped("wg")
}

// TestPSKFetchDoesNotBurnToken: the script may have to retry, so a GET must
// leave the staged key and its token exactly as they were.
func TestPSKFetchDoesNotBurnToken(t *testing.T) {
	db := openTestDBHandlers(t)
	enc := pskTestEnc(t)
	id, token := seedPSKNode(t, db, enc, "", store.DateAddMinutes(30))
	h := newPSKHandler(t, db, enc, nil)

	var first string
	for i := range 2 {
		rec := httptest.NewRecorder()
		h.Fetch(rec, pskGet(token))
		if rec.Code != http.StatusOK {
			t.Fatalf("call %d: status %d, want 200", i, rec.Code)
		}
		var body struct {
			PSK string `json:"psk"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !wireguard.ValidPresharedKey(body.PSK) {
			t.Fatalf("invalid psk %q", body.PSK)
		}
		if i == 0 {
			first = body.PSK
		} else if body.PSK != first {
			t.Fatal("second fetch returned a different key")
		}
	}
	var active sql.NullString
	if err := db.QueryRowContext(context.Background(),
		"SELECT wg_psk_enc FROM caddy_nodes WHERE id = ?", id).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active.Valid {
		t.Fatal("fetch activated the pending key")
	}
}

// TestPSKFetchRejectsBadAndExpired: bad, expired and missing tokens must be
// indistinguishable (404), or the endpoint becomes a token oracle.
func TestPSKFetchRejectsBadAndExpired(t *testing.T) {
	db := openTestDBHandlers(t)
	enc := pskTestEnc(t)
	_, expiredTok := seedPSKNode(t, db, enc, "", store.DateAddMinutes(-5))
	_, liveTok := seedPSKNode(t, db, enc, "", store.DateAddMinutes(30))
	h := newPSKHandler(t, db, enc, nil)

	cases := map[string]string{
		"expired":    expiredTok,
		"unknown":    strings.Repeat("a", 64),
		"wrong size": liveTok[:32],
		"non-hex":    strings.Repeat("g", 64),
		"empty":      "",
	}
	for name, tok := range cases {
		rec := httptest.NewRecorder()
		h.Fetch(rec, pskGet(tok))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", name, rec.Code)
		}
	}
}

// TestPSKConfirmPromotesAndIsIdempotent is the happy path: pending becomes
// active, the config is re-rendered, and a repeat confirm (lost response,
// script retry) answers 204 again instead of 404 - a 404 there would make
// the script roll the node back off a key the panel already committed.
func TestPSKConfirmPromotesAndIsIdempotent(t *testing.T) {
	db := openTestDBHandlers(t)
	enc := pskTestEnc(t)
	oldPSK, _ := wireguard.GeneratePresharedKey()
	id, token := seedPSKNode(t, db, enc, oldPSK, store.DateAddMinutes(30))
	rendered := 0
	h := newPSKHandler(t, db, enc, func(context.Context) error { rendered++; return nil })

	// Grab the staged key first so we can assert it is the one promoted.
	rec := httptest.NewRecorder()
	h.Fetch(rec, pskGet(token))
	var body struct {
		PSK string `json:"psk"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)

	req := pskConfirmReq(token)
	rec = httptest.NewRecorder()
	h.Confirm(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d, want 204", rec.Code)
	}
	if rendered != 1 {
		t.Fatalf("WriteWGConfig called %d times, want 1", rendered)
	}

	var active, pending, tokenHash sql.NullString
	if err := db.QueryRowContext(context.Background(),
		"SELECT wg_psk_enc, wg_psk_pending_enc, wg_psk_token_hash FROM caddy_nodes WHERE id = ?", id,
	).Scan(&active, &pending, &tokenHash); err != nil {
		t.Fatal(err)
	}
	got, err := enc.Decrypt(active.String)
	if err != nil {
		t.Fatal(err)
	}
	if got != body.PSK {
		t.Fatal("active key is not the one the node was handed")
	}
	if pending.Valid {
		t.Fatal("pending key survived the confirm")
	}
	if !tokenHash.Valid {
		t.Fatal("token cleared on confirm - a retried confirm would 404")
	}

	// Retry of a confirm whose response was lost: same 204, no re-render.
	rec = httptest.NewRecorder()
	h.Confirm(rec, pskConfirmReq(token))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("retry status %d, want 204", rec.Code)
	}
	if rendered != 1 {
		t.Fatalf("WriteWGConfig called %d times after the retry, want 1", rendered)
	}
	// A GET is still refused though: there is nothing staged any more.
	rec = httptest.NewRecorder()
	h.Fetch(rec, pskGet(token))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("post-confirm fetch status %d, want 404", rec.Code)
	}
}

// TestPSKConfirmCompensatesWithCancelledRequestContext: the two likeliest
// render failures are the request context expiring and the client
// disconnecting, so the compensating UPDATE must not ride on that context.
func TestPSKConfirmCompensatesWithCancelledRequestContext(t *testing.T) {
	db := openTestDBHandlers(t)
	enc := pskTestEnc(t)
	oldPSK, _ := wireguard.GeneratePresharedKey()
	id, token := seedPSKNode(t, db, enc, oldPSK, store.DateAddMinutes(30))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := newPSKHandler(t, db, enc, func(context.Context) error {
		cancel() // client walked away mid-render
		return errors.New("context canceled")
	})

	rec := httptest.NewRecorder()
	h.Confirm(rec, pskConfirmReq(token).WithContext(ctx))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", rec.Code)
	}

	var active, pending, tokenHash sql.NullString
	if err := db.QueryRowContext(context.Background(),
		"SELECT wg_psk_enc, wg_psk_pending_enc, wg_psk_token_hash FROM caddy_nodes WHERE id = ?", id,
	).Scan(&active, &pending, &tokenHash); err != nil {
		t.Fatal(err)
	}
	got, err := enc.Decrypt(active.String)
	if err != nil {
		t.Fatal(err)
	}
	if got != oldPSK {
		t.Fatal("compensation did not run on the cancelled request context - the panel kept the promoted key")
	}
	if !pending.Valid || !tokenHash.Valid {
		t.Fatal("pending key / token not restored, the operator cannot retry")
	}
}

// TestPSKFetchRequiresManagerPubKey: without it the script cannot tell the
// panel's [Peer] block from a hand-added one, so the panel must refuse
// rather than let it stamp the key onto every peer.
func TestPSKFetchRequiresManagerPubKey(t *testing.T) {
	db := openTestDBHandlers(t)
	enc := pskTestEnc(t)
	_, token := seedPSKNode(t, db, enc, "", store.DateAddMinutes(30))
	h := newPSKHandler(t, db, enc, nil)
	h.PeerPublicKey = func(context.Context) (string, error) { return "", errors.New("no keypair") }

	rec := httptest.NewRecorder()
	h.Fetch(rec, pskGet(token))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", rec.Code)
	}
}

// TestPSKFetchReturnsManagerPubKey: the script matches on it, so it has to
// be in the response next to the key.
func TestPSKFetchReturnsManagerPubKey(t *testing.T) {
	db := openTestDBHandlers(t)
	enc := pskTestEnc(t)
	_, token := seedPSKNode(t, db, enc, "", store.DateAddMinutes(30))
	h := newPSKHandler(t, db, enc, nil)

	rec := httptest.NewRecorder()
	h.Fetch(rec, pskGet(token))
	var body struct {
		PSK  string `json:"psk"`
		Peer string `json:"peer_public_key"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Peer != testManagerPubKey {
		t.Fatalf("peer_public_key = %q, want %q", body.Peer, testManagerPubKey)
	}
}

// TestPSKRateLimitFailsClosedWithoutRedis: Redis is optional here and these
// endpoints are unauthenticated, so the cap must still bite without it.
func TestPSKRateLimitFailsClosedWithoutRedis(t *testing.T) {
	h := &NodePSKHandler{
		DB:          func() *sql.DB { return nil },
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		PerIPPerMin: 3,
	}
	limited := 0
	for range 10 {
		rec := httptest.NewRecorder()
		h.Fetch(rec, pskGet(strings.Repeat("a", 64)))
		if rec.Code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited != 7 {
		t.Fatalf("got %d rate-limited of 10 with a cap of 3, want 7", limited)
	}
}

// TestPSKConfirmCompensatesOnRenderFailure: if our own wg0.conf cannot be
// written, the promotion must be undone and the caller told to roll back.
func TestPSKConfirmCompensatesOnRenderFailure(t *testing.T) {
	db := openTestDBHandlers(t)
	enc := pskTestEnc(t)
	oldPSK, _ := wireguard.GeneratePresharedKey()
	id, token := seedPSKNode(t, db, enc, oldPSK, store.DateAddMinutes(30))
	h := newPSKHandler(t, db, enc, func(context.Context) error { return errors.New("disk on fire") })

	req := pskConfirmReq(token)
	rec := httptest.NewRecorder()
	h.Confirm(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", rec.Code)
	}

	var active, pending, tokenHash sql.NullString
	if err := db.QueryRowContext(context.Background(),
		"SELECT wg_psk_enc, wg_psk_pending_enc, wg_psk_token_hash FROM caddy_nodes WHERE id = ?", id,
	).Scan(&active, &pending, &tokenHash); err != nil {
		t.Fatal(err)
	}
	got, err := enc.Decrypt(active.String)
	if err != nil {
		t.Fatal(err)
	}
	if got != oldPSK {
		t.Fatal("previous active key was not restored")
	}
	if !pending.Valid || !tokenHash.Valid {
		t.Fatal("pending key / token not restored, the operator cannot retry")
	}

	// And the restored token still works, so the retry is a real one.
	h2 := newPSKHandler(t, db, enc, func(context.Context) error { return nil })
	req = pskConfirmReq(token)
	rec = httptest.NewRecorder()
	h2.Confirm(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("retry status %d, want 204", rec.Code)
	}
}

package handlers

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/store"
	"github.com/host-yt/caddy-proxy-manager/internal/wireguard"
)

// clearReq builds a POST to the PSK clear route with chi's URL param bound.
func clearReq(id int64) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/admin/nodes/"+strconv.FormatInt(id, 10)+"/psk/clear", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", strconv.FormatInt(id, 10))
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

// TestNodesPSKClearKeepsStateWhenRenderFails covers the emergency exit's worst
// case. Clear is followed by the operator stripping the key on the node, so
// reporting success without having rewritten our own wg0.conf sends them to
// break a mesh that was still working - and hides that a retry is needed.
func TestNodesPSKClearKeepsStateWhenRenderFails(t *testing.T) {
	db := openTestDBHandlers(t)
	enc := pskTestEnc(t)
	psk, _ := wireguard.GeneratePresharedKey()
	id, _ := seedPSKNode(t, db, enc, psk, store.DateAddMinutes(30))

	h := &AdminHandlers{
		DB:            func() *sql.DB { return db },
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		WriteWGConfig: func(context.Context) error { return errors.New("disk on fire") },
	}
	rec := httptest.NewRecorder()
	h.NodesPSKClear(rec, clearReq(id))

	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "err=") {
		t.Errorf("render failure was not surfaced as an error: %s", loc)
	}
	if strings.Contains(loc, "PresharedKey") || strings.Contains(loc, "syncconf") {
		t.Errorf("node-side cleanup command offered even though the panel side did not change: %s", loc)
	}

	var active sql.NullString
	if err := db.QueryRowContext(context.Background(),
		"SELECT wg_psk_enc FROM caddy_nodes WHERE id = ?", id).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if !active.Valid {
		t.Fatal("PSK was dropped from the database even though the config write failed")
	}
	got, err := enc.Decrypt(active.String)
	if err != nil {
		t.Fatal(err)
	}
	if got != psk {
		t.Errorf("restored key does not match the original")
	}
}

// And the happy path still clears and still tells the operator what to run.
func TestNodesPSKClearSucceeds(t *testing.T) {
	db := openTestDBHandlers(t)
	enc := pskTestEnc(t)
	psk, _ := wireguard.GeneratePresharedKey()
	id, _ := seedPSKNode(t, db, enc, psk, store.DateAddMinutes(30))

	h := &AdminHandlers{
		DB:            func() *sql.DB { return db },
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		WriteWGConfig: func(context.Context) error { return nil },
	}
	rec := httptest.NewRecorder()
	h.NodesPSKClear(rec, clearReq(id))

	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "flash=") || strings.Contains(loc, "err=") {
		t.Errorf("expected a success flash, got: %s", loc)
	}
	// The node-side command must be one that works: `wg syncconf` cannot
	// REMOVE a preshared key, so a flash telling the operator to run it
	// promises a clear that never happens on the live interface.
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	flash := u.Query().Get("flash")
	if !strings.Contains(flash, "preshared-key /dev/null") {
		t.Errorf("flash does not tell the operator how to clear the live interface: %s", flash)
	}
	if strings.Contains(flash, "syncconf") {
		t.Errorf("flash still recommends syncconf, which cannot remove a key: %s", flash)
	}
	var active, pending, tokenHash sql.NullString
	if err := db.QueryRowContext(context.Background(),
		"SELECT wg_psk_enc, wg_psk_pending_enc, wg_psk_token_hash FROM caddy_nodes WHERE id = ?", id,
	).Scan(&active, &pending, &tokenHash); err != nil {
		t.Fatal(err)
	}
	if active.Valid || pending.Valid || tokenHash.Valid {
		t.Error("clear left PSK state behind")
	}
}

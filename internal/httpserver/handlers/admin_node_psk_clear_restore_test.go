package handlers

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// A failed clear must restore the staged token's expiry too; without it the
// restored token is rejected by the expiry-gated fetch/confirm endpoints.
func TestNodesPSKClearRestoresTokenExpiry(t *testing.T) {
	db := mtlsTLSEditDB(t)
	exp := time.Date(2090, 1, 2, 3, 4, 5, 0, time.UTC)
	if _, err := db.Exec(`UPDATE caddy_nodes SET wg_psk_enc = 'act', wg_psk_pending_enc = 'pend',
		wg_psk_token_hash = 'h', wg_psk_token_enc = 'tok', wg_psk_token_expires = ? WHERE id = 1`, exp); err != nil {
		t.Fatalf("seed: %v", err)
	}
	h := editFormHandlers(t, db)
	h.WriteWGConfig = func(context.Context) error { return errors.New("render boom") }

	req := httptest.NewRequest(http.MethodPost, "/admin/nodes/1/psk/clear", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "1")
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = middleware.ContextWithSession(ctx, &auth.Session{UserID: 1, Role: "super_admin"})
	h.NodesPSKClear(httptest.NewRecorder(), req.WithContext(ctx))

	var hash sql.NullString
	var got sql.NullTime
	if err := db.QueryRow(`SELECT wg_psk_token_hash, wg_psk_token_expires FROM caddy_nodes WHERE id = 1`).Scan(&hash, &got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if hash.String != "h" {
		t.Fatalf("token hash not restored: %+v", hash)
	}
	if !got.Valid || !got.Time.Equal(exp) {
		t.Errorf("token expiry not restored: got %+v, want %v", got, exp)
	}
}

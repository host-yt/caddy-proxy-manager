package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/wgpeer"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// Reissue only mints a new bootstrap token; the keypair is untouched, so the
// rotation age the scheduler reads must not move.
func TestTunnelsReissueKeepsRotationAge(t *testing.T) {
	db := mtlsTLSEditDB(t)
	const old = "2020-01-02 03:04:05"
	if _, err := db.Exec(`INSERT INTO customer_wg_peer (id, client_id, node_id, name, assigned_ip,
		last_rotated_at, last_key_rotation_at) VALUES (9, 1, 1, 'p', '100.96.0.9', ?, ?)`, old, old); err != nil {
		t.Fatalf("seed peer: %v", err)
	}
	h := editFormHandlers(t, db)
	h.WGPeers = &wgpeer.Service{DB: db, Logger: h.Logger}

	req := httptest.NewRequest(http.MethodPost, "/admin/tunnels/9/reissue", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "9")
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = middleware.ContextWithSession(ctx, &auth.Session{UserID: 1, Role: "super_admin"})
	rec := httptest.NewRecorder()
	h.TunnelsReissue(rec, req.WithContext(ctx))

	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM customer_wg_bootstrap WHERE peer_id = 9`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("reissue did not mint a token (n=%d err=%v, status %d)", n, err, rec.Code)
	}
	var a, b string
	if err := db.QueryRow(`SELECT last_rotated_at, last_key_rotation_at FROM customer_wg_peer WHERE id = 9`).Scan(&a, &b); err != nil {
		t.Fatalf("read peer: %v", err)
	}
	if fix := strings.NewReplacer("T", " "); fix.Replace(a[:19]) != old || fix.Replace(b[:19]) != old {
		t.Errorf("rotation timestamps moved on reissue: %q %q", a, b)
	}
}

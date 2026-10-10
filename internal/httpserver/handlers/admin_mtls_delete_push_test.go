package handlers

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/routes"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
)

// Deleting a CA must queue a durable push to the nodes that trusted it, or they
// keep accepting its certificates until drift reconcile notices.
func TestMTLSDeleteCA_PushesAffectedNodes(t *testing.T) {
	db := mtlsTLSEditDB(t)
	if _, err := db.Exec(`UPDATE routes SET require_client_cert = 1, mtls_ca_id = 1 WHERE id = 7`); err != nil {
		t.Fatal(err)
	}
	st, err := installstate.New(t.TempDir(), strings.Repeat("x", 32))
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := &AdminHandlers{
		DB:     func() *sql.DB { return db },
		Logger: logger,
		State:  st,
		// Long debounce: only the durable marker is observed, no live /load.
		Routes: &routes.Service{DB: db, Logger: logger, BgCtx: context.Background(), PushDebounceMs: 3_600_000},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/mtls/ca/1/delete", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "1")
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = middleware.ContextWithSession(ctx, &auth.Session{UserID: 1, Role: "super_admin"})
	rec := httptest.NewRecorder()
	h.MTLSDeleteCA(rec, req.WithContext(ctx))
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "err=") {
		t.Fatalf("delete failed: %s", loc)
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM mtls_cas WHERE id = 1`).Scan(&n)
	if n != 0 {
		t.Fatalf("CA still present")
	}
	_ = db.QueryRow(`SELECT COUNT(*) FROM node_push_pending WHERE node_id = 1`).Scan(&n)
	if n != 1 {
		t.Fatalf("no durable push queued for the node that trusted the CA")
	}
}

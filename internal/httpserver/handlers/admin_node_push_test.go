package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/routes"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// TestNodeUpdatePushesConfig guards the node edit form against silently
// declaring a capability the live config does not have yet. Every flag on
// that form feeds the generated Caddy config - the WAF and GeoIP handlers,
// PROXY protocol listeners, and the Caddy version gating the post-quantum
// curve - and node-level differences are invisible to route-level drift
// detection, so nothing else would ever reconcile them.
func TestNodeUpdatePushesConfig(t *testing.T) {
	db := openTestDBHandlers(t)
	defer db.Close()
	nodeID, cleanup := insertUnprobedNode(t, db)
	defer cleanup()

	var loads int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "load") {
			atomic.AddInt32(&loads, 1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if _, err := db.Exec("UPDATE caddy_nodes SET api_url = ? WHERE id = ?", srv.URL, nodeID); err != nil {
		t.Fatal(err)
	}

	h := &AdminHandlers{
		DB:     func() *sql.DB { return db },
		Logger: slog.New(slog.NewTextHandler(discardWriter{}, nil)),
		Routes: &routes.Service{DB: db, Logger: slog.New(slog.NewTextHandler(discardWriter{}, nil))},
	}
	form := url.Values{}
	form.Set("outbound_ips", "203.0.113.7")
	form.Set("caddy_version", "2.11.4")
	req := httptest.NewRequest(http.MethodPost,
		"/admin/nodes/"+fmt.Sprint(nodeID)+"/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", fmt.Sprint(nodeID))
	req = req.WithContext(middleware.ContextWithSession(
		context.WithValue(req.Context(), chi.RouteCtxKey, rctx),
		&auth.Session{UserID: 1, Role: "super_admin", Email: "a@example.com"}))

	rr := httptest.NewRecorder()
	h.NodesUpdate(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("NodesUpdate: got %d, want 303", rr.Code)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&loads) > 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Error("saving node capabilities pushed no config: the node keeps serving the old one while the panel reports the new capability as in effect")
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

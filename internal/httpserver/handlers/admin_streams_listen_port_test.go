package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

func TestStreamsUpdateListenPort(t *testing.T) {
	db := mtlsTLSEditDB(t)
	for _, s := range []string{
		`INSERT INTO stream_routes (id, service_id, caddy_node_id, protocol, listen_port, upstream_port)
		   VALUES (5, 1, 1, 'tcp', 15000, 15001)`,
		`INSERT INTO stream_routes (id, service_id, caddy_node_id, protocol, listen_port, upstream_port)
		   VALUES (6, 1, 1, 'tcp', 15002, 15003)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	h := editFormHandlers(t, db)
	h.Routes.Layer4ModuleAvailable = true

	post := func(port string) string {
		form := url.Values{"listen_port": {port}, "match_mode": {"any"}}
		req := httptest.NewRequest(http.MethodPost, "/admin/streams/5/edit", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", "5")
		ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
		ctx = middleware.ContextWithSession(ctx, &auth.Session{UserID: 1, Role: "super_admin"})
		rec := httptest.NewRecorder()
		h.StreamsUpdate(rec, req.WithContext(ctx))
		return rec.Header().Get("Location")
	}
	stored := func() int {
		var p int
		if err := db.QueryRow(`SELECT listen_port FROM stream_routes WHERE id = 5`).Scan(&p); err != nil {
			t.Fatal(err)
		}
		return p
	}

	for _, bad := range []string{"15002", "443", "0", "70000"} {
		if loc := post(bad); !strings.Contains(loc, "err=") || stored() != 15000 {
			t.Errorf("port %s accepted: loc=%s stored=%d", bad, loc, stored())
		}
	}
	if loc := post("15010"); strings.Contains(loc, "err=") || stored() != 15010 {
		t.Errorf("valid change failed: loc=%s stored=%d", loc, stored())
	}
}

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// A failure partway through the upstream list must leave neither the stream
// nor any earlier upstreams behind, and must not report success.
func TestStreamsCreateRollsBackOnUpstreamFailure(t *testing.T) {
	db := mtlsTLSEditDB(t)
	if _, err := db.Exec(`CREATE TRIGGER fail_second_upstream BEFORE INSERT ON stream_upstreams
		WHEN NEW.address = '10.0.0.12:9000' BEGIN SELECT RAISE(ABORT, 'boom'); END`); err != nil {
		t.Fatalf("trigger: %v", err)
	}
	h := editFormHandlers(t, db)
	h.Routes.Layer4ModuleAvailable = true

	form := url.Values{
		"protocol": {"tcp"}, "listen_port": {"15500"}, "upstream_port": {"9000"},
		"backend_ip": {"10.0.0.10"}, "node_id": {"1"}, "lb_policy": {"round_robin"},
		"upstreams_raw": {"10.0.0.11:9000\n10.0.0.12:9000\n10.0.0.13:9000"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/streams", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := middleware.ContextWithSession(context.Background(), &auth.Session{UserID: 1, Role: "super_admin"})
	rec := httptest.NewRecorder()
	h.StreamsCreate(rec, req.WithContext(ctx))

	var routes, ups int
	if err := db.QueryRow(`SELECT COUNT(*) FROM stream_routes WHERE listen_port = 15500`).Scan(&routes); err != nil {
		t.Fatalf("count routes: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM stream_upstreams`).Scan(&ups); err != nil {
		t.Fatalf("count upstreams: %v", err)
	}
	if routes != 0 || ups != 0 {
		t.Errorf("partial create committed: routes=%d upstreams=%d", routes, ups)
	}
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "created") {
		t.Errorf("reported success after upstream failure: %s", loc)
	}
}

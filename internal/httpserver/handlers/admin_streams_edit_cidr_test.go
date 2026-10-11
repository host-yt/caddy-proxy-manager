package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// The edit form posts both CIDR textareas back verbatim, so they must render
// the stored lists or any unrelated save silently clears access control.
func TestStreamsEditPrefillsCIDRLists(t *testing.T) {
	db := mtlsTLSEditDB(t)
	if _, err := db.Exec(`INSERT INTO stream_routes (id, service_id, caddy_node_id, protocol, listen_port, upstream_port,
		cidr_allow, cidr_deny) VALUES (5, 1, 1, 'tcp', 15000, 15001, '10.0.0.0/8,172.16.0.0/12', '192.0.2.0/24')`); err != nil {
		t.Fatalf("seed stream: %v", err)
	}
	h := editFormHandlers(t, db)

	req := httptest.NewRequest(http.MethodGet, "/admin/streams/5/edit", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "5")
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = middleware.ContextWithSession(ctx, &auth.Session{UserID: 1, Role: "super_admin"})
	rec := httptest.NewRecorder()
	h.StreamsEdit(rec, req.WithContext(ctx))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{">10.0.0.0/8,172.16.0.0/12</textarea>", ">192.0.2.0/24</textarea>"} {
		if !strings.Contains(body, want) {
			t.Errorf("edit form missing stored CIDR list %q", want)
		}
	}
}

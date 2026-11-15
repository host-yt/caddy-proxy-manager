package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/host-yt/caddy-proxy-manager/internal/adminscope"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// postHostEditScoped drives the edit as a client-scoped admin (user 2, scoped to client 1).
func postHostEditScoped(t *testing.T, db *sql.DB, form url.Values) string {
	t.Helper()
	h := editFormHandlers(t, db)
	h.AdminScope = adminscope.New(func() *sql.DB { return db })
	h.Routes.ExternalUpstreamAllowlist = []string{"origin.example"}
	req := httptest.NewRequest(http.MethodPost, "/admin/hosts/7/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "7")
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = middleware.ContextWithSession(ctx, &auth.Session{UserID: 2, Role: "admin", Restricted: true})
	rec := httptest.NewRecorder()
	h.HostsUpdate(rec, req.WithContext(ctx))
	return rec.Header().Get("Location") + rec.Body.String()
}

// Edit must not turn on a feature the plan withholds, as create refuses it.
func TestHostsUpdate_ScopedEditPlanGates(t *testing.T) {
	db := mtlsTLSEditDB(t)
	for _, q := range []string{
		`INSERT INTO users (id, email, password_hash, role, is_restricted) VALUES (2, 'scoped@b.c', 'x', 'admin', 1)`,
		`INSERT INTO admin_client_scope (admin_user_id, client_id) VALUES (2, 1)`,
		`INSERT INTO dns_providers (name, provider, api_token_enc) VALUES ('locked.example', 'cloudflare', 'x')`,
		`UPDATE plans SET wildcard_enabled = 0, external_proxy_enabled = 0`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	wild := baseEditForm()
	wild.Set("ssl", "1")
	wild.Set("wildcard_enabled", "1")
	wild.Set("wildcard_zone", "locked.example")
	if out := postHostEditScoped(t, db, wild); !strings.Contains(out, "wildcard certificates") {
		t.Errorf("wildcard: got %q, want plan refusal", out)
	}
	ext := baseEditForm()
	ext.Set("upstream_external", "1")
	ext.Set("external_host", "origin.example")
	ext.Set("port", "443")
	if out := postHostEditScoped(t, db, ext); !strings.Contains(out, "external+upstreams") {
		t.Errorf("external: got %q, want plan refusal", out)
	}
}

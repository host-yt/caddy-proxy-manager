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
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/routes"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// postHostEditAs is postHostEdit with the caller's role, since these gates are
// role-dependent.
func postHostEditAs(t *testing.T, db *sql.DB, role string, form url.Values) string {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	bg, cancel := context.WithCancel(context.Background())
	cancel() // no post-commit push at the fake node
	h := &AdminHandlers{
		DB:     func() *sql.DB { return db },
		Logger: logger,
		Routes: &routes.Service{DB: db, Logger: logger, BgCtx: bg},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/hosts/7/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "7")
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = middleware.ContextWithSession(ctx, &auth.Session{UserID: 1, Role: role})
	rec := httptest.NewRecorder()
	h.HostsUpdate(rec, req.WithContext(ctx))
	return rec.Header().Get("Location")
}

// The gate has to be wired into the save, not just exist: a scoped admin is
// refused and told why, a super_admin's resolver still stores.
func TestHostsUpdateGatesSubmittedResolver(t *testing.T) {
	db := mtlsTLSEditDB(t)

	form := baseEditForm()
	form.Set("dns_resolver_ip", "10.8.0.1")
	loc := postHostEditAs(t, db, "admin", form)
	if !strings.Contains(loc, "err=") || !strings.Contains(loc, "super_admin") {
		t.Fatalf("Location = %q, want a super_admin refusal", loc)
	}
	var stored string
	if err := db.QueryRow("SELECT COALESCE(dns_resolver_ip,'') FROM routes WHERE id = 7").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "" {
		t.Fatalf("refused save still wrote the resolver: %q", stored)
	}

	if loc := postHostEditAs(t, db, "super_admin", form); strings.Contains(loc, "err=") {
		t.Fatalf("super_admin save rejected: %s", loc)
	}
	if err := db.QueryRow("SELECT COALESCE(dns_resolver_ip,'') FROM routes WHERE id = 7").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "10.8.0.1" {
		t.Fatalf("super_admin resolver not stored, got %q", stored)
	}
}

// The SSO screen has to run on the save, or the route is only refused later,
// at push, with the host already dark.
func TestHostsUpdateScreensSSOProvider(t *testing.T) {
	db := mtlsTLSEditDB(t)

	form := baseEditForm()
	form.Set("sso_provider_url", "http://127.0.0.1:9000/outpost.goauthentik.io/auth/caddy")
	loc := postHostEditAs(t, db, "super_admin", form)
	if !strings.Contains(loc, "err=") || !strings.Contains(loc, "SSO+provider") {
		t.Fatalf("Location = %q, want an SSO provider refusal", loc)
	}
	var stored string
	if err := db.QueryRow("SELECT COALESCE(sso_provider_url,'') FROM routes WHERE id = 7").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "" {
		t.Fatalf("refused save still wrote the provider: %q", stored)
	}
}

// HPG-SEC-001a, write half: a resolver the tenant submits picks what the node
// dials without the panel screening the answer, so it needs the same waiver as
// node-side resolution - and the operator is told, never silently zeroed.
func TestResolverForSaveGatesSubmittedValues(t *testing.T) {
	for _, role := range []string{"admin", "reseller", "client", "viewer", ""} {
		if _, _, _, err := resolverForSave(role, "10.8.0.1", 0, "proxy", "app.example", 0); !errors.Is(err, errResolverNeedsWaiver) {
			t.Errorf("role %q: submitted resolver IP must be refused, got %v", role, err)
		}
		if _, _, _, err := resolverForSave(role, "", 7, "proxy", "app.example", 0); !errors.Is(err, errResolverNeedsWaiver) {
			t.Errorf("role %q: submitted resolver peer must be refused, got %v", role, err)
		}
	}
	ip, peer, auto, err := resolverForSave("super_admin", "10.8.0.1", 7, "proxy", "app.example", 0)
	if err != nil || ip != "10.8.0.1" || peer != 0 || auto {
		t.Errorf("super_admin keeps the IP and drops the peer, got %q %d %v %v", ip, peer, auto, err)
	}
}

// CRITICAL: the tunnel auto-bind is panel-generated, not tenant input. Gating
// it would break every scoped admin saving an ordinary tunnel route with a
// hostname backend.
func TestResolverForSaveExemptsTunnelAutoBind(t *testing.T) {
	ip, peer, auto, err := resolverForSave("admin", "", 0, "proxy", "app.internal", 42)
	if err != nil {
		t.Fatalf("auto-bind must not need the waiver: %v", err)
	}
	if ip != "" || peer != 42 || !auto {
		t.Fatalf("expected the peer auto-bound, got ip=%q peer=%d auto=%v", ip, peer, auto)
	}

	// An IP backend resolves nothing, and a redirect dials nothing: no bind.
	for _, c := range []struct{ kind, backend string }{
		{"proxy", "203.0.113.9"},
		{"redirect", "app.internal"},
	} {
		if _, peer, auto, err := resolverForSave("admin", "", 0, c.kind, c.backend, 42); err != nil || peer != 0 || auto {
			t.Errorf("%s/%s: expected no resolver, got peer=%d auto=%v err=%v", c.kind, c.backend, peer, auto, err)
		}
	}
	// A submitted value still loses to the gate even with a tunnel present.
	if _, _, _, err := resolverForSave("admin", "10.8.0.1", 0, "proxy", "app.internal", 42); !errors.Is(err, errResolverNeedsWaiver) {
		t.Errorf("submitted resolver must not ride in on the auto-bind path: %v", err)
	}
}

// HPG-SEC-001b, write half: the save screens the same dial target emission
// screens, so an operator is refused now instead of watching the route go dark.
func TestScreenSSOTargetMatchesEmission(t *testing.T) {
	infra := resolveTestInfra(t)
	ctx := context.Background()

	if err := screenSSOTarget(ctx, infra, "", ""); err != nil {
		t.Errorf("no SSO configured must stay allowed: %v", err)
	}
	for _, bad := range []string{
		"http://10.66.0.9:8080/outpost.goauthentik.io/auth/caddy", // control-plane mesh
		"https://203.0.113.7/outpost.goauthentik.io/auth/caddy",   // node public IP
		"http://10.0.0.5:2019/",                                   // node admin API port
		"not-a-url",
	} {
		if err := screenSSOTarget(ctx, infra, bad, ""); err == nil {
			t.Errorf("SSO provider %q must be refused at write time", bad)
		}
	}
	// A tunnel-bound provider dials the peer, so that is what gets screened.
	if err := screenSSOTarget(ctx, infra, "https://sso.example.com/outpost.goauthentik.io/auth/caddy", "10.77.0.2"); err != nil {
		t.Errorf("customer peer target must stay allowed: %v", err)
	}
	if err := screenSSOTarget(ctx, infra, "https://sso.example.com/outpost.goauthentik.io/auth/caddy", "10.66.0.9"); err == nil {
		t.Error("a bound peer pointing at the control plane must be refused")
	}
}

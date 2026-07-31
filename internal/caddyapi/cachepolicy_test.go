package caddyapi

import (
	"encoding/json"
	"strings"
	"testing"
)

func routeJSON(t *testing.T, r Route) string {
	t.Helper()
	b, err := json.Marshal(BuildRoute(r))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// An ordinary proxy route carries no HPG auth field, yet the upstream may
// authenticate a cookie itself: it must never be advertised as public.
func TestCacheDefaultsToPrivate(t *testing.T) {
	got := routeJSON(t, Route{
		ID: "1", Hosts: []string{"a.example.com"}, UpstreamIP: "10.0.0.1", UpstreamPort: 80,
		CacheEnabled: true, CacheTTLSeconds: 60, CacheModuleAvailable: true,
	})
	if strings.Contains(got, "public, max-age") {
		t.Error("plain cached route advertised as public without opt-in")
	}
	// The shared node cache must not hold caller-dependent content either.
	if strings.Contains(got, `"handler":"cache"`) {
		t.Error("shared cache emitted for a route not declared public")
	}
	if !strings.Contains(got, "private, max-age=60") {
		t.Errorf("expected private max-age, got: %s", got)
	}
}

func TestCachePublicOptIn(t *testing.T) {
	got := routeJSON(t, Route{
		ID: "2", Hosts: []string{"b.example.com"}, UpstreamIP: "10.0.0.1", UpstreamPort: 80,
		CacheEnabled: true, CacheTTLSeconds: 60, CacheModuleAvailable: true,
		CachePublic: true,
	})
	if !strings.Contains(got, "public, max-age=60") {
		t.Errorf("explicit opt-in should be public, got: %s", got)
	}
}

// A credentialled request must bypass the cache handler entirely and be told
// not to store, whatever the route flags say.
func TestCredentialledRequestsBypassCache(t *testing.T) {
	got := routeJSON(t, Route{
		ID: "3", Hosts: []string{"c.example.com"}, UpstreamIP: "10.0.0.1", UpstreamPort: 80,
		CacheEnabled: true, CacheTTLSeconds: 60, CacheModuleAvailable: true,
		CachePublic: true,
	})
	for _, want := range []string{`"Cookie"`, `"Authorization"`, "private, no-store", `"not"`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in: %s", want, got)
		}
	}
}

// CacheVary must not be able to drop credential headers from the cache key.
func TestCacheVaryKeepsCredentialHeaders(t *testing.T) {
	got := routeJSON(t, Route{
		ID: "4", Hosts: []string{"d.example.com"}, UpstreamIP: "10.0.0.1", UpstreamPort: 80,
		CacheEnabled: true, CacheTTLSeconds: 60, CacheModuleAvailable: true,
		CachePublic: true, CacheVary: []string{"Accept-Language"},
	})
	_ = got
	for _, want := range []string{"Accept-Language", "Cookie", "Authorization"} {
		if !strings.Contains(got, want) {
			t.Errorf("cache key lost %s: %s", want, got)
		}
	}
}

// Allow-list, not deny-list: an unknown or nested custom handler must suppress
// caching even though its name is not a known auth handler.
func TestCustomHandlersAllowList(t *testing.T) {
	cases := []struct {
		name  string
		raw   string
		gated bool
	}{
		{"empty", "", false},
		{"safe headers", `[{"handler":"headers"}]`, false},
		{"known auth", `[{"handler":"authentication"}]`, true},
		{"unknown handler", `[{"handler":"some_future_auth"}]`, true},
		{"nested subroute", `[{"handler":"headers","routes":[{"handle":[{"handler":"authentication"}]}]}]`, true},
		{"unparsable", `{`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := customHandlersAuth(c.raw); got != c.gated {
				t.Fatalf("customHandlersAuth(%s) = %v want %v", c.raw, got, c.gated)
			}
		})
	}
}

// /api* is broader than /api/*: the narrower, gated route must be emitted first.
func TestTrailingSlashOrdering(t *testing.T) {
	routes := []Route{
		{ID: "1", Hosts: []string{"x.example.com"}, PathPrefix: "/api", UpstreamIP: "10.0.0.1", UpstreamPort: 80},
		{ID: "2", Hosts: []string{"x.example.com"}, PathPrefix: "/api/", UpstreamIP: "10.0.0.2", UpstreamPort: 80,
			BasicAuthUser: "u", BasicAuthBcrypt: "$2a$x"},
	}
	sorted := SortRoutesForEmission(routes)
	if sorted[0].PathPrefix != "/api/" {
		t.Fatalf("gated /api/ must precede broader /api, got %q first", sorted[0].PathPrefix)
	}
}

// At equal specificity the gated route wins.
func TestGatedWinsAtEqualSpecificity(t *testing.T) {
	routes := []Route{
		{ID: "1", Hosts: []string{"y.example.com"}, PathPrefix: "/app", UpstreamIP: "10.0.0.1", UpstreamPort: 80},
		{ID: "2", Hosts: []string{"y.example.com"}, PathPrefix: "/abc", UpstreamIP: "10.0.0.2", UpstreamPort: 80,
			PortalProtect: true, PortalDial: "127.0.0.1:8080"},
	}
	sorted := SortRoutesForEmission(routes)
	if !RouteAuthGated(sorted[0]) {
		t.Fatalf("gated route must sort first, got %q", sorted[0].PathPrefix)
	}
}

// A public cache must never store or replay an upstream Set-Cookie: one
// visitor's session cookie handed to the next is session fixation.
func TestPublicCacheStripsSetCookie(t *testing.T) {
	got := routeJSON(t, Route{
		ID: "5", Hosts: []string{"e.example.com"}, UpstreamIP: "10.0.0.1", UpstreamPort: 80,
		CacheEnabled: true, CacheTTLSeconds: 60, CacheModuleAvailable: true,
		CachePublic: true,
	})
	if !strings.Contains(got, `"Set-Cookie"`) || !strings.Contains(got, `"deferred":true`) {
		t.Errorf("public cache route must strip Set-Cookie before the cache: %s", got)
	}
	// The stripper must sit after the cache handler, i.e. between it and the
	// upstream, so Souin never sees the header at all.
	ci, si := strings.Index(got, `"handler":"cache"`), strings.Index(got, `"Set-Cookie"`)
	if ci < 0 || si < 0 || si < ci {
		t.Errorf("Set-Cookie stripper must follow the cache handler: cache=%d strip=%d", ci, si)
	}
}

// Caching off does not make a restricted route safe to share: the upstream can
// still send Cache-Control: public and a CDN would replay it past the ACL.
func TestRestrictedRouteWithoutCacheStillPrivate(t *testing.T) {
	for name, r := range map[string]Route{
		"ip-blacklist": {ID: "6", Hosts: []string{"f.example.com"}, UpstreamIP: "10.0.0.1", UpstreamPort: 80,
			AccessDeny: []string{"203.0.113.0/24"}},
		"basic-auth": {ID: "7", Hosts: []string{"g2.example.com"}, UpstreamIP: "10.0.0.1", UpstreamPort: 80,
			BasicAuthUser: "u", BasicAuthBcrypt: "$2a$x"},
	} {
		got := routeJSON(t, r)
		if !strings.Contains(got, "private, no-store") {
			t.Errorf("%s: uncached restricted route must be no-store: %s", name, got)
		}
	}
}

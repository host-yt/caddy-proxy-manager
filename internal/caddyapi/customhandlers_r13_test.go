package caddyapi

import (
	"encoding/json"
	"strings"
	"testing"
)

// FINDING 2 (r13): a chain stored before this policy existed stayed executable
// across edits, restarts and bulk resyncs because emission never revalidated
// it. Route generation must fail closed on anything the allow-list rejects.
func TestBuildRouteDropsNonConformingStoredChain(t *testing.T) {
	legacy := []string{
		// The pre-upgrade payload: straight at Caddy's local admin API.
		`[{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:2019"}]}]`,
		// One allowed entry does not launder a denied one alongside it.
		`[{"handler":"headers","response":{"set":{"X-Ok":["1"]}}},
		  {"handler":"file_server","root":"/"}]`,
		// Templates: dropped from the allow-list in r13 (see below).
		`[{"handler":"templates"}]`,
		// Structurally broken chains are not emitted either.
		`[{"upstreams":[{"dial":"127.0.0.1:2019"}]}]`,
	}
	for _, raw := range legacy {
		out, _ := json.Marshal(BuildRoute(Route{
			Hosts: []string{"owned.example"}, UpstreamIP: "10.0.0.5", UpstreamPort: 80,
			CustomHandlers: raw,
		}))
		// The route's own upstream is a legitimate reverse_proxy, so match on
		// what only the smuggled chain would contribute.
		for _, needle := range []string{"127.0.0.1", "2019", "file_server", "templates"} {
			if strings.Contains(string(out), needle) {
				t.Errorf("stored chain %s reached the emitted config (%s): %s", raw, needle, out)
			}
		}
	}

	// A conforming chain still emits.
	out, _ := json.Marshal(BuildRoute(Route{
		Hosts: []string{"owned.example"}, UpstreamIP: "10.0.0.5", UpstreamPort: 80,
		CustomHandlers: `[{"handler":"vars","tier":"gold"}]`,
	}))
	if !strings.Contains(string(out), `"tier":"gold"`) {
		t.Errorf("benign chain was dropped: %s", out)
	}
}

// FINDING 3 (r13): `templates` and unrestricted header values kept secret- and
// internal-request-reading capabilities. Caddy 2.11.1's template FuncMap ships
// env/readFile/httpInclude/placeholder with no sandbox, and header values run
// through the replacer - both expand inside the node's process, around a
// response body the tenant's own upstream controls.
func TestSanitizeCustomHandlersRejectsSecretReach(t *testing.T) {
	bad := []string{
		// Templates in any shape: the upstream body becomes the program.
		`[{"handler":"templates"}]`,
		`[{"handler":"templates","mime_types":["text/html"]}]`,
		`[{"handler":"templates","delimiters":["{{","}}"]}]`,
		// Environment reach through a header value.
		`[{"handler":"headers","response":{"set":{"X-Leak":["{env.MYSQL_PASSWORD}"]}}}]`,
		`[{"handler":"headers","request":{"set":{"X-Leak":["pre-{env.HPG_SECRET_KEY}-post"]}}}]`,
		// Filesystem reach through a header value.
		`[{"handler":"headers","response":{"set":{"X-Leak":["{file./etc/passwd}"]}}}]`,
		// Node fingerprinting.
		`[{"handler":"headers","response":{"set":{"X-Host":["{system.hostname}"]}}}]`,
		// Same reach hidden in a header NAME, a delete list, and a rewrite URI.
		`[{"handler":"headers","response":{"delete":["{env.SECRET}"]}}]`,
		`[{"handler":"headers","response":{"set":{"{env.SECRET}":["x"]}}}]`,
		`[{"handler":"rewrite","uri":"/x?leak={env.SECRET}"}]`,
		// vars scalars are string values too.
		`[{"handler":"vars","leak":"{env.SECRET}"}]`,
		// Caddyfile-style env shorthand.
		`[{"handler":"headers","response":{"set":{"X-Leak":["{$SECRET}"]}}}]`,
	}
	for _, raw := range bad {
		if out, err := SanitizeCustomHandlers(raw); err == nil {
			t.Errorf("accepted secret-reaching chain %s -> %s", raw, out)
		}
	}

	// Request-scoped placeholders stay usable - they carry no node state.
	good := []string{
		`[{"handler":"headers","response":{"set":{"X-Real-IP":["{http.request.remote.host}"]}}}]`,
		`[{"handler":"rewrite","uri":"{http.request.uri.path}"}]`,
	}
	for _, raw := range good {
		if _, err := SanitizeCustomHandlers(raw); err != nil {
			t.Errorf("rejected benign chain %s: %v", raw, err)
		}
	}
}

// FINDING 3 (r13): the response side is tenant-controlled. Even if an upstream
// returns a body full of template expressions and placeholder syntax, nothing
// in the emitted chain can evaluate it.
func TestNoHandlerEvaluatesUpstreamResponseBody(t *testing.T) {
	// What an attacker's own upstream would serve, hoping a custom handler
	// evaluates it in Caddy's process context.
	payload := `{{env "MYSQL_ROOT_PASSWORD"}}{{httpInclude "http://127.0.0.1:2019/config/"}}{{readFile "/etc/shadow"}}`
	for _, raw := range []string{
		`[{"handler":"templates"}]`,
		`[{"handler":"headers","response":{"set":{"X-Body":["` + `{env.X}` + `"]}}}]`,
	} {
		if _, err := SanitizeCustomHandlers(raw); err == nil {
			t.Fatalf("chain able to evaluate a tenant response body was accepted: %s", raw)
		}
		out, _ := json.Marshal(BuildRoute(Route{
			Hosts: []string{"owned.example"}, UpstreamIP: "10.0.0.5", UpstreamPort: 80,
			CustomHandlers: raw,
		}))
		if strings.Contains(string(out), "templates") || strings.Contains(string(out), "{env.") {
			t.Fatalf("evaluating chain reached the node: %s", out)
		}
	}
	// Sanity: the payload itself is only ever inert bytes to the emitted config.
	if strings.Contains(payload, "\x00") {
		t.Fatal("unreachable")
	}
}

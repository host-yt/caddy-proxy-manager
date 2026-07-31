package caddyapi

import (
	"strings"
	"testing"
)

// FINDING 1 (r14): dropping a rejected chain but keeping the route live exposed
// the backend the chain was protecting (auth, deny, body limits, maintenance).
// The whole route must be quarantined instead.
func TestBuildRouteQuarantinesRouteWithRejectedChain(t *testing.T) {
	rejected := []string{
		// Legacy gate the flat allow-list cannot vouch for.
		`[{"handler":"authentication","providers":{}}]`,
		// Allow-listed name, Caddy-invalid schema (finding 2).
		`[{"handler":"headers","request":"not-an-object"}]`,
		`[{"handler":"headers","response":{"set":{"X-Ok":"one-string"}}}]`,
		`[{"handler":"encode","encodings":{"br":{}}}]`,
		`[{"handler":"encode","prefer":["br"]}]`,
		`[{"handler":"encode","minimum_length":"1024"}]`,
		`[{"handler":"request_body","read_timeout":"30s"}]`,
		`[{"handler":"rewrite","path_regexp":[{"find":"([","replace":"x"}]}]`,
		`[{"handler":"rewrite","uri":123}]`,
		`[{"handler":"headers","response":{"replace":{"X":[{"search_regexp":"("}]}}}]`,
	}
	for _, raw := range rejected {
		out := mustJSON(Route{
			ID: "9", Hosts: []string{"gated.example"}, UpstreamIP: "10.0.0.5", UpstreamPort: 80,
			CustomHandlers: raw,
		})
		// The backend must not be reachable at all.
		if strings.Contains(out, "reverse_proxy") || strings.Contains(out, "10.0.0.5") {
			t.Errorf("chain %s left an unguarded proxy: %s", raw, out)
		}
		// Operator-visible: 503 + a header naming the cause.
		if !strings.Contains(out, `"status_code":503`) ||
			!strings.Contains(out, `"X-Hpg-Quarantine":["custom-handlers"]`) {
			t.Errorf("chain %s did not quarantine visibly: %s", raw, out)
		}
		// terminal so no catch-all can serve the host behind the quarantine.
		if !strings.Contains(out, `"terminal":true`) {
			t.Errorf("chain %s quarantine is not terminal: %s", raw, out)
		}
		// And the reason reaches the audit trail, not just the wire.
		if CustomHandlerQuarantine(Route{CustomHandlers: raw}) == "" {
			t.Errorf("chain %s reported no quarantine reason", raw)
		}
	}
}

// A schema-conforming chain is untouched: the route still proxies and the chain
// still emits.
func TestBuildRouteEmitsValidChain(t *testing.T) {
	valid := []string{
		`[{"handler":"headers","response":{"set":{"X-Ok":["1"]},"deferred":true}}]`,
		`[{"handler":"headers","request":{"delete":["X-Forwarded-Host"]}}]`,
		`[{"handler":"encode","encodings":{"gzip":{"level":5},"zstd":{"level":"fastest"}},"prefer":["zstd","gzip"],"minimum_length":512}]`,
		`[{"handler":"rewrite","uri":"/api{http.request.uri.path}","path_regexp":[{"find":"^/v1/(.*)$","replace":"/$1"}]}]`,
		`[{"handler":"request_body","max_size":1048576,"read_timeout":30000000000}]`,
		`[{"handler":"vars","tier":"gold"}]`,
	}
	for _, raw := range valid {
		if _, err := SanitizeCustomHandlers(raw); err != nil {
			t.Fatalf("valid chain rejected %s: %v", raw, err)
		}
		out := mustJSON(Route{
			ID: "9", Hosts: []string{"ok.example"}, UpstreamIP: "10.0.0.5", UpstreamPort: 80,
			CustomHandlers: raw,
		})
		if strings.Contains(out, "X-Hpg-Quarantine") {
			t.Errorf("valid chain %s was quarantined: %s", raw, out)
		}
		if !strings.Contains(out, "reverse_proxy") {
			t.Errorf("valid chain %s lost the route's proxy: %s", raw, out)
		}
	}
}

// FINDING 2 (r14): allow-listed names with values Caddy cannot unmarshal used to
// pass write-time validation and could fail a whole node /load on emission.
func TestSanitizeCustomHandlersEnforcesTypes(t *testing.T) {
	bad := map[string]string{
		"headers.request scalar":  `[{"handler":"headers","request":"nope"}]`,
		"headers unknown op":      `[{"handler":"headers","request":{"append":{"X":["1"]}}}]`,
		"header value not array":  `[{"handler":"headers","request":{"set":{"X":"1"}}}]`,
		"header delete not array": `[{"handler":"headers","response":{"delete":"X"}}]`,
		"require bad status":      `[{"handler":"headers","response":{"require":{"status_code":["200"]}}}]`,
		"encode unknown module":   `[{"handler":"encode","encodings":{"brotli":{}}}]`,
		"encode gzip level str":   `[{"handler":"encode","encodings":{"gzip":{"level":"5"}}}]`,
		"encode unknown sub-key":  `[{"handler":"encode","encodings":{"gzip":{"quality":5}}}]`,
		"encode min length str":   `[{"handler":"encode","minimum_length":"1024"}]`,
		"rewrite uri number":      `[{"handler":"rewrite","uri":7}]`,
		"rewrite regexp broken":   `[{"handler":"rewrite","path_regexp":[{"find":"(","replace":"x"}]}]`,
		"rewrite regexp empty":    `[{"handler":"rewrite","path_regexp":[{"find":"","replace":"x"}]}]`,
		"rewrite substr limit":    `[{"handler":"rewrite","uri_substring":[{"find":"a","limit":"2"}]}]`,
		"request_body duration":   `[{"handler":"request_body","write_timeout":"30s"}]`,
		"request_body max_size":   `[{"handler":"request_body","max_size":"1mb"}]`,
	}
	for name, raw := range bad {
		if out, err := SanitizeCustomHandlers(raw); err == nil {
			t.Errorf("%s: accepted Caddy-invalid chain %s -> %s", name, raw, out)
		}
	}
}

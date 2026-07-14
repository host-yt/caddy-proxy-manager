package caddyapi

import (
	"encoding/json"
	"strings"
	"testing"
)

// srv0Of extracts apps.http.servers.srv0 from a BuildNodeConfig result.
func srv0Of(cfg map[string]any) map[string]any {
	return cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["srv0"].(map[string]any)
}

func baseRoutes() []Route {
	return []Route{
		{ID: "1", Hosts: []string{"a.example.com"}, UpstreamIP: "10.0.0.1", UpstreamPort: 8080},
	}
}

// TestProxyProtocolDisabled_NoListenerWrappersKey is the critical regression
// guard: existing nodes (ProxyProtocolIn unset) must see zero config change,
// or every fleet on this build would drift-resync forever.
func TestProxyProtocolDisabled_NoListenerWrappersKey(t *testing.T) {
	cfg := BuildNodeConfig(baseRoutes(), NodeSettings{ACMEEmail: "a@b.c"})
	srv0 := srv0Of(cfg)
	if _, ok := srv0["listener_wrappers"]; ok {
		t.Fatalf("listener_wrappers must be absent when disabled, got: %s", jsonStr(srv0))
	}
}

// TestProxyProtocolEnabled_WithAllow checks the full shape: proxy_protocol
// wrapper before tls, timeout mapped from ms, allow list in given order.
func TestProxyProtocolEnabled_WithAllow(t *testing.T) {
	cfg := BuildNodeConfig(baseRoutes(), NodeSettings{
		ACMEEmail:              "a@b.c",
		ProxyProtocolIn:        true,
		ProxyProtocolAllow:     "10.0.0.0/8, 203.0.113.5/32",
		ProxyProtocolTimeoutMs: 5000,
	})
	srv0 := srv0Of(cfg)
	lw, ok := srv0["listener_wrappers"].([]any)
	if !ok || len(lw) != 2 {
		t.Fatalf("expected 2-entry listener_wrappers, got: %s", jsonStr(srv0["listener_wrappers"]))
	}
	pp := lw[0].(map[string]any)
	if pp["wrapper"] != "proxy_protocol" {
		t.Fatalf("first wrapper must be proxy_protocol, got %v", pp["wrapper"])
	}
	if pp["timeout"] != "5s" {
		t.Fatalf("want timeout 5s, got %v", pp["timeout"])
	}
	allow, ok := pp["allow"].([]string)
	if !ok || len(allow) != 2 || allow[0] != "10.0.0.0/8" || allow[1] != "203.0.113.5/32" {
		t.Fatalf("allow list mismatch, want ordered [10.0.0.0/8 203.0.113.5/32], got %v", pp["allow"])
	}
	tlsWrap := lw[1].(map[string]any)
	if tlsWrap["wrapper"] != "tls" {
		t.Fatalf("second wrapper must be tls (explicit), got %v", tlsWrap["wrapper"])
	}
}

// TestProxyProtocolEnabled_EmptyAllow: an empty allow-list must omit the
// "allow" key entirely (accept from anywhere), not emit an empty array.
func TestProxyProtocolEnabled_EmptyAllow(t *testing.T) {
	cfg := BuildNodeConfig(baseRoutes(), NodeSettings{
		ACMEEmail:       "a@b.c",
		ProxyProtocolIn: true,
	})
	srv0 := srv0Of(cfg)
	s := jsonStr(srv0["listener_wrappers"])
	if strings.Contains(s, `"allow"`) {
		t.Fatalf("allow key must be omitted when empty, got: %s", s)
	}
	if !strings.Contains(s, `"wrapper":"proxy_protocol"`) || !strings.Contains(s, `"wrapper":"tls"`) {
		t.Fatalf("expected both wrappers present, got: %s", s)
	}
}

// TestProxyProtocolTimeout_MsMapping exercises the ms->duration-string
// mapping directly, including the zero-value fallback to the 5s default.
func TestProxyProtocolTimeout_MsMapping(t *testing.T) {
	cases := []struct {
		ms   int
		want string
	}{
		{0, "5s"},        // unset -> default
		{5000, "5s"},     // whole seconds collapse to "Ns"
		{1500, "1500ms"}, // sub-second precision preserved
		{250, "250ms"},
	}
	for _, c := range cases {
		cfg := BuildNodeConfig(baseRoutes(), NodeSettings{
			ACMEEmail:              "a@b.c",
			ProxyProtocolIn:        true,
			ProxyProtocolTimeoutMs: c.ms,
		})
		srv0 := srv0Of(cfg)
		lw := srv0["listener_wrappers"].([]any)
		pp := lw[0].(map[string]any)
		if pp["timeout"] != c.want {
			t.Errorf("ms=%d: want timeout %q, got %v", c.ms, c.want, pp["timeout"])
		}
	}
}

// TestBuildProxyProtocolWrappers_DirectUnit exercises the helper in
// isolation (no full BuildNodeConfig) for a quick shape check with json.Marshal.
func TestBuildProxyProtocolWrappers_DirectUnit(t *testing.T) {
	if got := buildProxyProtocolWrappers(NodeSettings{}); got != nil {
		t.Fatalf("disabled must return nil, got %v", got)
	}
	got := buildProxyProtocolWrappers(NodeSettings{
		ProxyProtocolIn:        true,
		ProxyProtocolAllow:     "1.2.3.4/32",
		ProxyProtocolTimeoutMs: 250,
	})
	b, _ := json.Marshal(got)
	want := `[{"allow":["1.2.3.4/32"],"timeout":"250ms","wrapper":"proxy_protocol"},{"wrapper":"tls"}]`
	if string(b) != want {
		t.Fatalf("shape mismatch\nwant: %s\ngot:  %s", want, string(b))
	}
}

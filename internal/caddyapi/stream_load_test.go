//go:build integration

// Fixture validation for the caddy-l4 (layer4) config shapes. Each generated
// advanced-stream config is POSTed to a real Caddy admin /load endpoint built
// with the caddy-l4 module (deploy/caddy/Dockerfile pins @v0.1.1). A schema
// mismatch surfaces as a 400 with Caddy's own error, so this is what lets the
// streams advanced options ship as production-ready rather than "experimental".
//
// Run against a Caddy admin endpoint (default http://127.0.0.1:2019):
//
//	CADDY_ADMIN=http://127.0.0.1:2019 go test -tags=integration ./internal/caddyapi/...
package caddyapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

func l4Admin() string {
	if v := os.Getenv("CADDY_ADMIN"); v != "" {
		return v
	}
	return "http://127.0.0.1:2019"
}

// postLoad sends the config to Caddy's /load and returns status + body.
func postLoad(t *testing.T, admin string, cfg map[string]any) (int, string) {
	t.Helper()
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, admin+"/load", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	hc := &http.Client{Timeout: 10 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		t.Skipf("caddy admin not reachable at %s (start a caddy-l4 build): %v", admin, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// TestLayer4LoadShapes loads every advanced-stream config shape into a real
// Caddy+caddy-l4 and asserts /load accepts it (200). Upstreams need not be
// reachable - provisioning validates the schema without dialing them.
func TestLayer4LoadShapes(t *testing.T) {
	admin := l4Admin()
	cases := []struct {
		name   string
		routes []StreamRoute
	}{
		{"plain_tcp", []StreamRoute{{ID: 1, Protocol: "tcp", ListenPort: 15001, UpstreamIP: "127.0.0.1", UpstreamPort: 9, Upstreams: []StreamUpstream{{Address: "127.0.0.1:9"}}}}},
		{"udp", []StreamRoute{{ID: 2, Protocol: "udp", ListenPort: 15002, Upstreams: []StreamUpstream{{Address: "127.0.0.1:9"}}}}},
		{"sni_match", []StreamRoute{{ID: 3, Protocol: "tcp", ListenPort: 15003, MatchMode: "sni", MatchValues: []string{"db.example.com"}, Upstreams: []StreamUpstream{{Address: "127.0.0.1:9"}}}}},
		{"http_host_match", []StreamRoute{{ID: 4, Protocol: "tcp", ListenPort: 15004, MatchMode: "http_host", MatchValues: []string{"app.example.com"}, Upstreams: []StreamUpstream{{Address: "127.0.0.1:9"}}}}},
		{"lb_multi", []StreamRoute{{ID: 5, Protocol: "tcp", ListenPort: 15005, LBPolicy: "least_conn", Upstreams: []StreamUpstream{{Address: "127.0.0.1:9", Weight: 3}, {Address: "127.0.0.1:10", Weight: 1}}}}},
		{"proxy_proto_in", []StreamRoute{{ID: 6, Protocol: "tcp", ListenPort: 15006, ProxyProtoIn: "v2", Upstreams: []StreamUpstream{{Address: "127.0.0.1:9"}}}}},
		{"proxy_proto_out", []StreamRoute{{ID: 7, Protocol: "tcp", ListenPort: 15007, ProxyProtoOut: "v1", Upstreams: []StreamUpstream{{Address: "127.0.0.1:9"}}}}},
		{"cidr_deny_allow", []StreamRoute{{ID: 8, Protocol: "tcp", ListenPort: 15008, CIDRDeny: []string{"192.168.0.0/16"}, CIDRAllow: []string{"10.0.0.0/8"}, Upstreams: []StreamUpstream{{Address: "127.0.0.1:9"}}}}},
		{"full_advanced", []StreamRoute{{ID: 9, Protocol: "tcp", ListenPort: 15009, MatchMode: "sni", MatchValues: []string{"db.example.com"}, LBPolicy: "least_conn", ProxyProtoIn: "v2", ProxyProtoOut: "v2", CIDRDeny: []string{"172.31.0.0/24"}, CIDRAllow: []string{"172.16.0.0/12"}, Upstreams: []StreamUpstream{{Address: "127.0.0.1:9", Weight: 2}, {Address: "127.0.0.1:10"}}}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := map[string]any{"apps": map[string]any{"layer4": buildLayer4App(c.routes)}}
			status, body := postLoad(t, admin, cfg)
			if status != http.StatusOK {
				t.Fatalf("/load rejected %s config (status %d): %s", c.name, status, body)
			}
		})
	}
	// Reset to an empty config so the test Caddy doesn't keep the listeners.
	_, _ = postLoad(t, admin, map[string]any{"admin": map[string]any{"listen": "127.0.0.1:2019"}})
}

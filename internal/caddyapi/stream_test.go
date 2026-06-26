package caddyapi

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestBuildLayer4AppEmpty confirms nil is returned for empty input so we
// never emit an empty servers map.
func TestBuildLayer4AppEmpty(t *testing.T) {
	if got := buildLayer4App(nil); got != nil {
		t.Fatalf("expected nil for empty routes, got %v", got)
	}
}

// TestBuildLayer4AppSingleTCP is the baseline fixture: single TCP route with
// one upstream - the only path validated end-to-end against real Caddy.
func TestBuildLayer4AppSingleTCP(t *testing.T) {
	routes := []StreamRoute{
		{ID: 1, Protocol: "tcp", ListenPort: 25565, UpstreamIP: "10.0.0.5", UpstreamPort: 25565},
	}
	app := buildLayer4App(routes)
	b, _ := json.Marshal(app)
	s := string(b)

	for _, want := range []string{
		`"tcp/:25565"`,
		`"handler":"proxy"`,
		`"dial":["10.0.0.5:25565"]`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("single-TCP missing %q\nfull: %s", want, s)
		}
	}
	// Must not emit matcher block for "any" mode.
	if strings.Contains(s, `"match"`) {
		t.Errorf("any-mode must not emit match block\nfull: %s", s)
	}
}

// TestBuildLayer4AppBothProto confirms "both" protocol creates two server
// entries - tcp_<port> and udp_<port>.
func TestBuildLayer4AppBothProto(t *testing.T) {
	routes := []StreamRoute{
		{ID: 2, Protocol: "both", ListenPort: 19132, UpstreamIP: "10.0.0.9", UpstreamPort: 19132},
	}
	app := buildLayer4App(routes)
	b, _ := json.Marshal(app)
	s := string(b)

	for _, want := range []string{
		`"tcp/:19132"`,
		`"udp/:19132"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("both-proto missing %q\nfull: %s", want, s)
		}
	}
}

// TestBuildLayer4AppMultiUpstreamLB checks multi-upstream + LB policy emission.
// NOT fixture-validated against real Caddy (load_balancing schema).
func TestBuildLayer4AppMultiUpstreamLB(t *testing.T) {
	routes := []StreamRoute{
		{
			ID: 3, Protocol: "tcp", ListenPort: 3306,
			Upstreams: []StreamUpstream{
				{Address: "10.0.0.1:3306", Weight: 2},
				{Address: "10.0.0.2:3306", Weight: 1},
			},
			LBPolicy: "round_robin",
		},
	}
	app := buildLayer4App(routes)
	b, _ := json.Marshal(app)
	s := string(b)

	for _, want := range []string{
		`"10.0.0.1:3306"`,
		`"10.0.0.2:3306"`,
		`"weight":2`,
		`"load_balancing"`,
		`"round_robin"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("multi-upstream LB missing %q\nfull: %s", want, s)
		}
	}
}

// TestBuildLayer4AppSNIMatcher checks SNI matcher JSON shape.
// NOT fixture-validated against real Caddy (tls.sni schema).
func TestBuildLayer4AppSNIMatcher(t *testing.T) {
	routes := []StreamRoute{
		{
			ID: 4, Protocol: "tcp", ListenPort: 443,
			UpstreamIP: "10.0.1.1", UpstreamPort: 8443,
			MatchMode:   "sni",
			MatchValues: []string{"db.example.com", "db2.example.com"},
		},
	}
	app := buildLayer4App(routes)
	b, _ := json.Marshal(app)
	s := string(b)

	for _, want := range []string{
		`"match"`,
		`"tls"`,
		`"sni"`,
		`"db.example.com"`,
		`"db2.example.com"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("SNI matcher missing %q\nfull: %s", want, s)
		}
	}
}

// TestBuildLayer4AppHTTPHostMatcher checks http_host matcher JSON shape.
// NOT fixture-validated against real Caddy (http.host schema).
func TestBuildLayer4AppHTTPHostMatcher(t *testing.T) {
	routes := []StreamRoute{
		{
			ID: 5, Protocol: "tcp", ListenPort: 8080,
			UpstreamIP: "10.0.2.1", UpstreamPort: 8080,
			MatchMode:   "http_host",
			MatchValues: []string{"api.example.com"},
		},
	}
	app := buildLayer4App(routes)
	b, _ := json.Marshal(app)
	s := string(b)

	for _, want := range []string{
		`"match"`,
		`"http"`,
		`"host"`,
		`"api.example.com"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("http_host matcher missing %q\nfull: %s", want, s)
		}
	}
}

// TestBuildLayer4AppProxyProtoIn checks listener_wrappers for proxy-protocol in.
// NOT fixture-validated against real Caddy (proxy_protocol wrapper schema).
func TestBuildLayer4AppProxyProtoIn(t *testing.T) {
	routes := []StreamRoute{
		{
			ID: 6, Protocol: "tcp", ListenPort: 5432,
			UpstreamIP: "10.0.3.1", UpstreamPort: 5432,
			ProxyProtoIn: "v2",
		},
	}
	app := buildLayer4App(routes)
	b, _ := json.Marshal(app)
	s := string(b)

	for _, want := range []string{
		`"listener_wrappers"`,
		`"wrapper":"proxy_protocol"`,
		`"versions":["2"]`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("proxy-protocol-in missing %q\nfull: %s", want, s)
		}
	}
}

// TestBuildLayer4AppProxyProtoOut checks per-upstream proxy-protocol version emission.
// NOT fixture-validated against real Caddy (proxy handler proxy_protocol schema).
func TestBuildLayer4AppProxyProtoOut(t *testing.T) {
	routes := []StreamRoute{
		{
			ID: 7, Protocol: "tcp", ListenPort: 5433,
			UpstreamIP: "10.0.4.1", UpstreamPort: 5432,
			ProxyProtoOut: "v1",
		},
	}
	app := buildLayer4App(routes)
	b, _ := json.Marshal(app)
	s := string(b)

	for _, want := range []string{
		`"proxy_protocol"`,
		`"version":"1"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("proxy-protocol-out missing %q\nfull: %s", want, s)
		}
	}
}

// TestBuildLayer4AppCIDR checks remote_ip handler for CIDR allow/deny.
// NOT fixture-validated against real Caddy (remote_ip handler schema).
func TestBuildLayer4AppCIDR(t *testing.T) {
	routes := []StreamRoute{
		{
			ID: 8, Protocol: "tcp", ListenPort: 6379,
			UpstreamIP: "10.0.5.1", UpstreamPort: 6379,
			CIDRAllow: []string{"10.0.0.0/8"},
			CIDRDeny:  []string{"10.99.0.0/16"},
		},
	}
	app := buildLayer4App(routes)
	b, _ := json.Marshal(app)
	s := string(b)

	for _, want := range []string{
		`"handler":"remote_ip"`,
		`"allow":["10.0.0.0/8"]`,
		`"deny":["10.99.0.0/16"]`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("CIDR ACL missing %q\nfull: %s", want, s)
		}
	}
	// remote_ip must appear before proxy in handler list.
	remoteIPIdx := strings.Index(s, `"remote_ip"`)
	proxyIdx := strings.Index(s, `"proxy"`)
	if remoteIPIdx == -1 || proxyIdx == -1 || remoteIPIdx > proxyIdx {
		t.Errorf("remote_ip handler must precede proxy handler\nfull: %s", s)
	}
}

// TestBuildLayer4AppFullAdvanced exercises all advanced features together.
// All caddy-l4 specific fields are NOT fixture-validated against real Caddy.
func TestBuildLayer4AppFullAdvanced(t *testing.T) {
	routes := []StreamRoute{
		{
			ID: 9, Protocol: "tcp", ListenPort: 9000,
			Upstreams: []StreamUpstream{
				{Address: "10.0.10.1:9000", Weight: 3},
				{Address: "10.0.10.2:9000", Weight: 1},
			},
			MatchMode:     "sni",
			MatchValues:   []string{"db.corp.internal"},
			LBPolicy:      "least_conn",
			ProxyProtoIn:  "v2",
			ProxyProtoOut: "v2",
			CIDRAllow:     []string{"172.16.0.0/12"},
			CIDRDeny:      []string{"172.31.0.0/24"},
		},
	}
	app := buildLayer4App(routes)
	b, _ := json.Marshal(app)
	s := string(b)

	wants := []string{
		`"tcp/:9000"`,
		`"listener_wrappers"`,
		`"wrapper":"proxy_protocol"`,
		`"versions":["2"]`,
		`"match"`,
		`"tls"`,
		`"sni"`,
		`"db.corp.internal"`,
		`"handler":"remote_ip"`,
		`"allow":["172.16.0.0/12"]`,
		`"deny":["172.31.0.0/24"]`,
		`"handler":"proxy"`,
		`"10.0.10.1:9000"`,
		`"10.0.10.2:9000"`,
		`"load_balancing"`,
		`"least_conn"`,
		`"proxy_protocol"`,
		`"version":"2"`,
	}
	for _, want := range wants {
		if !strings.Contains(s, want) {
			t.Errorf("full-advanced missing %q\nfull: %s", want, s)
		}
	}
}

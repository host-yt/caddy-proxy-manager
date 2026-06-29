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

// TestBuildLayer4AppProxyProtoIn checks the proxy_protocol receive handler.
// caddy-l4 exposes inbound PROXY protocol as a handler (not a listener wrapper).
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

	if !strings.Contains(s, `"handler":"proxy_protocol"`) {
		t.Errorf("proxy-protocol-in must emit a proxy_protocol handler\nfull: %s", s)
	}
	for _, bad := range []string{`"listener_wrappers"`, `"wrapper"`, `"versions"`} {
		if strings.Contains(s, bad) {
			t.Errorf("proxy-protocol-in must NOT emit %q (wrong schema)\nfull: %s", bad, s)
		}
	}
	// The receive handler must run before the proxy handler.
	if i, j := strings.Index(s, `"handler":"proxy_protocol"`), strings.Index(s, `"handler":"proxy"`); i == -1 || j == -1 || i > j {
		t.Errorf("proxy_protocol handler must precede proxy handler\nfull: %s", s)
	}
}

// TestBuildLayer4AppProxyProtoOut checks the upstream proxy-protocol string field.
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

	if !strings.Contains(s, `"proxy_protocol":"v1"`) {
		t.Errorf("proxy-protocol-out must be a plain \"v1\" string\nfull: %s", s)
	}
}

// TestBuildLayer4AppCIDR checks remote_ip matcher + terminal close routes.
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
		`"remote_ip":{"ranges":["10.99.0.0/16"]}`,         // deny via matcher
		`"not":[{"remote_ip":{"ranges":["10.0.0.0/8"]}}]`, // allow-list closes the rest
		`"handler":"close"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("CIDR ACL missing %q\nfull: %s", want, s)
		}
	}
	if strings.Contains(s, `"handler":"remote_ip"`) {
		t.Errorf("remote_ip is a matcher, must not be emitted as a handler\nfull: %s", s)
	}
	// The close routes must precede the proxy route.
	if i, j := strings.Index(s, `"handler":"close"`), strings.Index(s, `"handler":"proxy"`); i == -1 || j == -1 || i > j {
		t.Errorf("ACL close routes must precede the proxy route\nfull: %s", s)
	}
}

// TestBuildLayer4AppProxyProtocol checks v2 PROXY protocol on both directions.
func TestBuildLayer4AppProxyProtocol(t *testing.T) {
	routes := []StreamRoute{
		{
			ID: 10, Protocol: "tcp", ListenPort: 5432,
			UpstreamIP: "10.0.0.3", UpstreamPort: 5432,
			ProxyProtoIn:  "v2",
			ProxyProtoOut: "v2",
		},
	}
	app := buildLayer4App(routes)
	b, _ := json.Marshal(app)
	s := string(b)

	for _, want := range []string{
		`"handler":"proxy_protocol"`, // inbound receive handler
		`"proxy_protocol":"v2"`,      // outbound string on the proxy handler
	} {
		if !strings.Contains(s, want) {
			t.Errorf("proxy-protocol v2 in+out missing %q\nfull: %s", want, s)
		}
	}
}

// TestBuildLayer4AppProxyProtoBeforeACL guards the access-control ordering: when
// PROXY protocol is accepted, the decoder must run BEFORE the remote_ip ACL so
// the ACL matches the real client, not the upstream LB socket peer. caddy-l4
// matchers on sibling routes see the raw connection, so the ACL must live in a
// subroute that runs after the proxy_protocol handler.
func TestBuildLayer4AppProxyProtoBeforeACL(t *testing.T) {
	routes := []StreamRoute{
		{
			ID: 12, Protocol: "tcp", ListenPort: 7000,
			UpstreamIP: "10.0.0.1", UpstreamPort: 7000,
			ProxyProtoIn: "v2",
			CIDRDeny:     []string{"203.0.113.0/24"},
		},
	}
	app := buildLayer4App(routes)
	b, _ := json.Marshal(app)
	s := string(b)

	pp := strings.Index(s, `"handler":"proxy_protocol"`)
	sub := strings.Index(s, `"handler":"subroute"`)
	acl := strings.Index(s, `"remote_ip"`)
	if pp == -1 || sub == -1 || acl == -1 {
		t.Fatalf("expected proxy_protocol + subroute + remote_ip\nfull: %s", s)
	}
	if !(pp < sub && sub < acl) {
		t.Errorf("PROXY decode must precede subroute ACL (pp=%d sub=%d acl=%d)\nfull: %s", pp, sub, acl, s)
	}
}

// TestBuildLayer4AppCIDRDeny checks both deny and allow CIDR sets as close routes.
func TestBuildLayer4AppCIDRDeny(t *testing.T) {
	routes := []StreamRoute{
		{
			ID: 11, Protocol: "tcp", ListenPort: 8080,
			UpstreamIP: "10.0.1.1", UpstreamPort: 8080,
			CIDRDeny:  []string{"192.168.0.0/16"},
			CIDRAllow: []string{"10.0.0.0/8"},
		},
	}
	app := buildLayer4App(routes)
	b, _ := json.Marshal(app)
	s := string(b)

	for _, want := range []string{
		`"remote_ip":{"ranges":["192.168.0.0/16"]}`,
		`"not":[{"remote_ip":{"ranges":["10.0.0.0/8"]}}]`,
		`"handler":"close"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("CIDR deny/allow missing %q\nfull: %s", want, s)
		}
	}
}

// TestBuildLayer4AppFullAdvanced exercises all advanced features together.
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
		`"remote_ip":{"ranges":["172.31.0.0/24"]}`,
		`"not":[{"remote_ip":{"ranges":["172.16.0.0/12"]}}]`,
		`"handler":"close"`,
		`"tls":{"sni":["db.corp.internal"]}`,
		`"handler":"proxy_protocol"`,
		`"handler":"proxy"`,
		`"10.0.10.1:9000"`,
		`"10.0.10.2:9000"`,
		`"load_balancing":{"selection_policy":{"policy":"least_conn"}}`,
		`"proxy_protocol":"v2"`,
	}
	for _, want := range wants {
		if !strings.Contains(s, want) {
			t.Errorf("full-advanced missing %q\nfull: %s", want, s)
		}
	}
	for _, bad := range []string{`"listener_wrappers"`, `"handler":"remote_ip"`, `"version":"2"`} {
		if strings.Contains(s, bad) {
			t.Errorf("full-advanced must not emit %q (wrong schema)\nfull: %s", bad, s)
		}
	}
}

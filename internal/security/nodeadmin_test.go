package security

import "testing"

func TestUnauthenticatedNodeAdminURL(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"http://10.66.0.2:2019", true},           // the shipped remote-node topology
		{"http://10.66.0.2:2021", false},          // node-agent admin proxy
		{"http://caddy:2019", false},              // compose-local, bridge only
		{"http://127.0.0.1:2019", false},          // node-local, agent side
		{"http://[::1]:2019", false},              // IPv6 loopback
		{"http://[fd00::2]:2019", true},           // remote IPv6
		{"http://10.66.0.2:2020", true},           // remapped admin port - no longer an escape
		{"http://10.66.0.2", true},                // implicit :80 in front of the admin API
		{"https://node2.example.com:2019", true},  // hostname instead of a literal IP
		{"https://node2.example.com", true},       // dotted name on any port
		{"https://node2.example.com:2021", false}, // the node-agent proxy
		{"unix:///sockets/caddy-admin.sock", false},
		{"", false},            // caller validates shape
		{"::not a url", false}, //
	}
	for _, c := range cases {
		if got := UnauthenticatedNodeAdminURL(c.url); got != c.want {
			t.Errorf("UnauthenticatedNodeAdminURL(%q) = %v, want %v", c.url, got, c.want)
		}
	}
}

func TestRejectUnauthenticatedNodeAdminURL(t *testing.T) {
	if err := RejectUnauthenticatedNodeAdminURL("http://10.66.0.2:2019"); err == nil {
		t.Fatal("expected a raw remote admin URL to be refused")
	}
	if err := RejectUnauthenticatedNodeAdminURL("http://10.66.0.2:2021"); err != nil {
		t.Fatalf("admin-proxy URL must be accepted: %v", err)
	}
	// SEC-002 re-verification: a remapped port and a hostname used to walk
	// straight past the guard.
	for _, u := range []string{"http://10.66.0.2:2020", "http://node2.example.com:2019"} {
		if err := RejectUnauthenticatedNodeAdminURL(u); err == nil {
			t.Fatalf("%s must be refused: it reaches a raw admin API over a network", u)
		}
	}
	t.Setenv(AllowUnauthenticatedNodeAdminEnv, "1")
	if err := RejectUnauthenticatedNodeAdminURL("http://10.66.0.2:2019"); err != nil {
		t.Fatalf("escape hatch must restore the legacy path: %v", err)
	}
}

// An operator whose admin proxy does not listen on 2021 must be able to say so
// without turning the guard off for the whole fleet.
func TestAdminProxyPortsEnv(t *testing.T) {
	t.Setenv(AdminProxyPortsEnv, "8443, 2021")
	if UnauthenticatedNodeAdminURL("https://node2.example.com:8443") {
		t.Error("a declared admin-proxy port must not be flagged")
	}
	if !UnauthenticatedNodeAdminURL("https://node2.example.com:8444") {
		t.Error("an undeclared port must stay flagged")
	}
}

func TestRejectSingleLabelNodeAdminURL(t *testing.T) {
	t.Setenv("CADDY_ADMIN_URL", "http://proxy-caddy:2019")
	t.Setenv(AllowUnauthenticatedNodeAdminEnv, "1") // escape hatch covers raw admin URLs, not this
	for _, u := range []string{"http://node2:2019", "http://node2:2021", "https://node2.:2019"} {
		if err := RejectUnauthenticatedNodeAdminURL(u); err == nil {
			t.Errorf("%s must be refused at registration", u)
		}
	}
	for _, u := range []string{"http://caddy:2019", "http://proxy-caddy:2019", "http://localhost:2019",
		"http://10.66.0.2:2021", "http://[fd00::2]:2021", "https://node2.example.com:2021",
		"unix:///sockets/caddy-admin.sock"} {
		if err := RejectSingleLabelNodeAdminURL(u); err != nil {
			t.Errorf("%s must be accepted: %v", u, err)
		}
	}
}

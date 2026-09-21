package security

import "testing"

func TestUnauthenticatedNodeAdminURL(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"http://10.66.0.2:2019", true},     // the shipped remote-node topology
		{"http://10.66.0.2:2021", false},    // node-agent admin proxy
		{"http://caddy:2019", false},        // compose-local, bridge only
		{"http://127.0.0.1:2019", false},    // node-local, agent side
		{"http://[::1]:2019", false},        // IPv6 loopback
		{"http://[fd00::2]:2019", true},     // remote IPv6
		{"http://10.66.0.2", false},         // not the admin port
		{"https://node.example.com", false}, // hostname, no admin port
		{"", false},                         // caller validates shape
		{"::not a url", false},              //
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
	t.Setenv(AllowUnauthenticatedNodeAdminEnv, "1")
	if err := RejectUnauthenticatedNodeAdminURL("http://10.66.0.2:2019"); err != nil {
		t.Fatalf("escape hatch must restore the legacy path: %v", err)
	}
}

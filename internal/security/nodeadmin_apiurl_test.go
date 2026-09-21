package security

import "testing"

func TestValidNodeAPIURL(t *testing.T) {
	ok := []string{"http://caddy:2019", "https://node.example:2021", "unix:///sockets/caddy-admin.sock"}
	for _, u := range ok {
		if !ValidNodeAPIURL(u) {
			t.Errorf("ValidNodeAPIURL(%q) = false, want true", u)
		}
	}
	bad := []string{"", "caddy:2019", "unix://", "unix:///", "file:///etc/passwd", "ftp://x"}
	for _, u := range bad {
		if ValidNodeAPIURL(u) {
			t.Errorf("ValidNodeAPIURL(%q) = true, want false", u)
		}
	}
}

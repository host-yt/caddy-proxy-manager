package caddyapi

import "testing"

func TestScreenDialTarget(t *testing.T) {
	// Verified against caddy 2.11.4: a reverse_proxy upstream of
	// "unix//path.sock" is dialed by Caddy itself, so it must never survive
	// screening; host:port forms must.
	bad := []string{
		"unix//sockets/caddy-admin.sock",
		"unix+h2c//sockets/caddy-admin.sock",
		"UNIX//sockets/caddy-admin.sock",
		"unixgram//sockets/x.sock",
		"fd/3",
		" unix//sockets/x.sock ",
	}
	for _, d := range bad {
		if err := ScreenDialTarget(d); err == nil {
			t.Errorf("ScreenDialTarget(%q) = nil, want error", d)
		}
	}
	good := []string{"10.0.0.5:8080", "[::1]:8080", "backend.internal:443", ""}
	for _, d := range good {
		if err := ScreenDialTarget(d); err != nil {
			t.Errorf("ScreenDialTarget(%q) = %v, want nil", d, err)
		}
	}
}

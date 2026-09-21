package streamguard

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

// HPG-SEC-001: the three HTTP upstream paths share this screener, so the whole
// policy is asserted here once.
func TestScreenHTTPBackend(t *testing.T) {
	infra := testInfra(t)
	lookupAddrs = func(_ context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "rebind.example.com":
			return []netip.Addr{netip.MustParseAddr("198.51.100.9"), netip.MustParseAddr("127.0.0.1")}, nil
		case "sneaky.example.com":
			return []netip.Addr{netip.MustParseAddr("10.66.0.4")}, nil // control mesh
		case "origin.example.com":
			return []netip.Addr{netip.MustParseAddr("198.51.100.10")}, nil
		}
		return nil, errors.New("nxdomain")
	}
	t.Cleanup(func() {
		lookupAddrs = func(ctx context.Context, host string) ([]netip.Addr, error) { return nil, errors.New("disabled") }
	})

	cases := []struct {
		name    string
		host    string
		port    int
		wantErr bool
	}{
		{"caddy admin api port", "198.51.100.10", 2019, true},
		{"loopback literal", "127.0.0.1", 8080, true},
		{"cloud metadata", "169.254.169.254", 80, true},
		{"node public ip", "203.0.113.7", 8080, true},
		{"control mesh member", "10.66.0.9", 8080, true},
		{"node hostname", "node1.example.com", 8080, true},
		{"tunnel gateway", "100.96.0.1", 8080, true},
		{"hostname resolving to node mesh", "sneaky.example.com", 8080, true},
		{"multi-record with loopback", "rebind.example.com", 8080, true},
		{"customer rfc1918 origin", "10.0.0.5", 8080, false},
		{"customer tunnel peer", "100.96.7.20", 8080, false},
		{"public origin", "origin.example.com", 443, false},
		{"empty host", "", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := infra.ScreenHTTPBackend(context.Background(), tc.host, tc.port)
			if tc.wantErr != (err != nil) {
				t.Fatalf("ScreenHTTPBackend(%q,%d) = %v, wantErr=%v", tc.host, tc.port, err, tc.wantErr)
			}
		})
	}

	// An unresolvable name is a distinct, tolerable outcome for callers whose
	// target is resolved node-side; everything else is a hard block.
	err := infra.ScreenHTTPBackend(context.Background(), "only-on-the-node", 8080)
	if !errors.Is(err, ErrUnresolved) {
		t.Fatalf("unresolvable host: got %v, want ErrUnresolved", err)
	}
	if err := infra.ScreenHTTPTargetLiteral("only-on-the-node", 8080); err != nil {
		t.Fatalf("literal screen must not resolve: %v", err)
	}
	if err := infra.ScreenHTTPTargetLiteral("node1.example.com", 8080); err == nil {
		t.Fatal("literal screen must still deny a node hostname")
	}
}

// The deny set must also carry the services the panel itself talks to, by
// service name - a tenant route to "caddy" would reach the admin API vhost.
func TestEnvInfraDeniesControlPlaneServices(t *testing.T) {
	t.Setenv("CADDY_ADMIN_URL", "http://caddy:2019")
	t.Setenv("APP_INTERNAL_HOST", "app")
	t.Setenv("DB_HOST", "mariadb")
	t.Setenv("REDIS_ADDR", "redis:6379")
	infra := New()
	infra.addEnvInfra()
	for _, h := range []string{"caddy", "app", "mariadb", "redis"} {
		if !infra.Blocked(h) {
			t.Errorf("%q must be denied", h)
		}
	}
	// A DB on a shared LAN box must not take the whole host out of service.
	t.Setenv("DB_HOST", "192.168.1.10")
	shared := New()
	shared.addEnvInfra()
	if shared.Blocked("192.168.1.10") {
		t.Error("a bare DB IP must not deny the whole host")
	}
}

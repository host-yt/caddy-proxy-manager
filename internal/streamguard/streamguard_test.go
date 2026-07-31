package streamguard

import (
	"context"
	"net/netip"
	"testing"
)

func testInfra(t *testing.T) *InfraTargets {
	t.Helper()
	infra := New()
	infra.Add("10.66.0.1")
	infra.Add("203.0.113.7")
	infra.Add("node1.example.com")
	infra.AddURLHost("http://10.66.0.5:2019")
	infra.AddTunnelGateway("100.96.0.0/16")
	p, err := netip.ParsePrefix("10.66.0.0/24")
	if err != nil {
		t.Fatalf("prefix: %v", err)
	}
	infra.AddPrefix(p)
	return infra
}

func TestInfraTargetsHostnameDeny(t *testing.T) {
	infra := testInfra(t)
	if !infra.Blocked("node1.example.com") {
		t.Error("node public hostname should be denied")
	}
	if !infra.Blocked("NODE1.example.com.") {
		t.Error("hostname deny should be case- and trailing-dot-insensitive")
	}
	if infra.Blocked("backend.tenant.example") {
		t.Error("unrelated hostname should not be denied")
	}
}

// withResolver swaps the resolver for the duration of one test.
func withResolver(t *testing.T, fn func(context.Context, string) ([]netip.Addr, error)) {
	t.Helper()
	prev := lookupAddrs
	lookupAddrs = fn
	t.Cleanup(func() { lookupAddrs = prev })
}

// A DNS server that alternates between a safe and an internal answer must not
// get an unvalidated address pinned: validation and pinning share ONE lookup.
func TestScreenAndPinAlternatingDNSAnswers(t *testing.T) {
	infra := testInfra(t)
	calls := 0
	answers := [][]netip.Addr{
		{netip.MustParseAddr("198.51.100.10")},   // first answer: public
		{netip.MustParseAddr("169.254.169.254")}, // second answer: metadata
	}
	withResolver(t, func(context.Context, string) ([]netip.Addr, error) {
		a := answers[min(calls, len(answers)-1)]
		calls++
		return a, nil
	})

	pinned, err := infra.ScreenAndPin(context.Background(), "rebind.example", 8080)
	if err != nil {
		t.Fatalf("expected the first validated answer to be accepted: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected exactly one lookup, got %d", calls)
	}
	if pinned != "198.51.100.10" {
		t.Fatalf("expected the pinned address to come from the validated answer, got %s", pinned)
	}
}

// Every address in the answer set is validated, not just the pinned one.
func TestScreenAndPinRejectsMixedAnswerSet(t *testing.T) {
	infra := testInfra(t)
	withResolver(t, func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("198.51.100.10"),
			netip.MustParseAddr("127.0.0.1"),
		}, nil
	})
	if _, err := infra.ScreenAndPin(context.Background(), "mixed.example", 8080); err == nil {
		t.Error("expected a mixed safe/loopback answer set to be rejected")
	}

	withResolver(t, func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("198.51.100.10"),
			netip.MustParseAddr("10.66.0.9"), // control-plane mesh
		}, nil
	})
	if _, err := infra.ScreenAndPin(context.Background(), "mixed2.example", 8080); err == nil {
		t.Error("expected an answer inside the control-plane mesh to be rejected")
	}
}

func TestScreenAndPinDeniesAdminPort(t *testing.T) {
	infra := testInfra(t)
	if _, err := infra.ScreenAndPin(context.Background(), "192.0.2.10", 2019); err == nil {
		t.Error("port 2019 must be denied everywhere")
	}
}

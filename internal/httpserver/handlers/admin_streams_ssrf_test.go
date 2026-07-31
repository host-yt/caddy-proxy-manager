package handlers

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"
)

// testInfra mirrors what loadInfraTargets builds for a deployment with one
// managed node on the WG mesh plus a customer tunnel subnet.
func testInfra(t *testing.T) *infraTargets {
	t.Helper()
	infra := &infraTargets{
		addrs: make(map[netip.Addr]struct{}),
		hosts: make(map[string]struct{}),
	}
	infra.add("10.66.0.1")   // control plane
	infra.add("203.0.113.7") // node public IP
	infra.add("node1.example.com")
	infra.addURLHost("http://10.66.0.5:2019")
	infra.addTunnelGateway("100.96.0.0/16")
	p, err := netip.ParsePrefix("10.66.0.0/24")
	if err != nil {
		t.Fatalf("prefix: %v", err)
	}
	infra.nets = append(infra.nets, p)
	return infra
}

// TestScreenStreamUpstreamsBlocksInternalAddresses covers the shared SSRF
// screen used by both StreamsCreate and StreamsUpdate, so the update path
// can't regress into accepting internal-network upstreams.
func TestScreenStreamUpstreamsBlocksInternalAddresses(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()
	infra := testInfra(t)

	blocked := []string{
		"127.0.0.1:2019",     // loopback - Caddy admin API
		"169.254.169.254:80", // link-local - cloud metadata
		"224.0.0.1:53",       // multicast
	}
	for _, addr := range blocked {
		if _, err := screenStreamUpstreamsWith(ctx, infra, logger, []upstreamEntry{{Address: addr, Weight: 1}}); err == nil {
			t.Errorf("expected %s to be blocked", addr)
		}
	}
}

// A managed node's own private/WG address must be refused even though the
// RFC1918 backend policy is deliberately permissive.
func TestScreenStreamUpstreamsBlocksManagedNodeAddresses(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()
	infra := testInfra(t)

	blocked := []string{
		"10.66.0.5:2019",   // node WG address, admin API
		"10.66.0.5:8080",   // node WG address, any port
		"10.66.0.9:8080",   // any address inside the control-plane mesh
		"10.66.0.1:8080",   // control plane
		"203.0.113.7:8080", // node public IP
		"100.96.0.1:8080",  // node tunnel-subnet gateway
		"192.0.2.10:2019",  // admin port anywhere
	}
	for _, addr := range blocked {
		if _, err := screenStreamUpstreamsWith(ctx, infra, logger, []upstreamEntry{{Address: addr, Weight: 1}}); err == nil {
			t.Errorf("expected %s to be blocked", addr)
		}
	}
}

func TestScreenStreamUpstreamsAllowsPrivateNet(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()
	infra := testInfra(t)

	// Ordinary tenant RFC1918 backends and customer tunnel peers stay allowed.
	allowed := []string{"10.0.0.5:8080", "192.168.1.20:3000", "100.96.0.7:8080"}
	for _, addr := range allowed {
		out, err := screenStreamUpstreamsWith(ctx, infra, logger, []upstreamEntry{{Address: addr, Weight: 1}})
		if err != nil {
			t.Errorf("expected %s to be allowed, got %v", addr, err)
			continue
		}
		if len(out) != 1 || out[0].Address != addr {
			t.Errorf("expected %s to pass through unchanged, got %+v", addr, out)
		}
	}
}

func TestInfraTargetsHostnameDeny(t *testing.T) {
	infra := testInfra(t)
	if !infra.blocked("node1.example.com") {
		t.Error("node public hostname should be denied")
	}
	if !infra.blocked("NODE1.example.com.") {
		t.Error("hostname deny should be case- and trailing-dot-insensitive")
	}
	if infra.blocked("backend.tenant.example") {
		t.Error("unrelated hostname should not be denied")
	}
}

func TestInfraTargetsFailsClosedWithoutDB(t *testing.T) {
	if _, err := loadInfraTargets(context.Background(), nil); err == nil {
		t.Error("expected loadInfraTargets to fail closed without a db")
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := screenStreamUpstreams(context.Background(), nil, logger, []upstreamEntry{{Address: "10.0.0.5:8080", Weight: 1}}); err == nil {
		t.Error("expected screenStreamUpstreams to fail closed without a db")
	}
}

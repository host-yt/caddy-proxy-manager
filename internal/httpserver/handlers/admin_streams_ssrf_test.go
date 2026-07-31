package handlers

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/streamguard"
)

// testInfra mirrors what streamguard.LoadInfraTargets builds for a deployment
// with one managed node on the WG mesh plus a customer tunnel subnet.
func testInfra(t *testing.T) *streamguard.InfraTargets {
	t.Helper()
	infra := streamguard.New()
	infra.Add("10.66.0.1")   // control plane
	infra.Add("203.0.113.7") // node public IP
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

func TestInfraTargetsFailsClosedWithoutDB(t *testing.T) {
	if _, err := streamguard.LoadInfraTargets(context.Background(), nil); err == nil {
		t.Error("expected LoadInfraTargets to fail closed without a db")
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := loadInfraOrFail(context.Background(), nil, logger); err == nil {
		t.Error("expected the screen to fail closed without a db")
	}
}

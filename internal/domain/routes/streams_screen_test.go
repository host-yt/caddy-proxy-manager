package routes

import (
	"context"
	"net/netip"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
	"github.com/host-yt/caddy-proxy-manager/internal/streamguard"
)

func screenTestInfra(t *testing.T) *streamguard.InfraTargets {
	t.Helper()
	infra := streamguard.New()
	infra.Add("203.0.113.7") // node public IP
	p, err := netip.ParsePrefix("10.66.0.0/24")
	if err != nil {
		t.Fatalf("prefix: %v", err)
	}
	infra.AddPrefix(p)
	return infra
}

// Legacy rows stored before target screening existed must not be re-emitted by
// boot push, manual resync or drift recovery.
func TestScreenStreamSetQuarantinesLegacyInfraTargets(t *testing.T) {
	infra := screenTestInfra(t)
	in := []caddyapi.StreamRoute{
		{ID: 1, ListenPort: 5000, UpstreamIP: "10.0.0.5", UpstreamPort: 8080},
		{ID: 2, ListenPort: 5001, UpstreamIP: "10.66.0.9", UpstreamPort: 2019}, // node admin API
		{ID: 3, ListenPort: 5002, UpstreamIP: "203.0.113.7", UpstreamPort: 8080},
		{ID: 4, ListenPort: 5003, UpstreamIP: "10.0.0.6", UpstreamPort: 8080,
			Upstreams: []caddyapi.StreamUpstream{{Address: "10.66.0.5:2019", Weight: 1}}},
	}
	kept, rejected := screenStreamSet(context.Background(), infra, in)

	if len(kept) != 1 || kept[0].ID != 1 {
		t.Fatalf("expected only the safe stream to be emitted, got %+v", kept)
	}
	if len(rejected) != 3 {
		t.Fatalf("expected 3 quarantined streams, got %d", len(rejected))
	}
	for _, r := range rejected {
		if r.cause == nil {
			t.Errorf("stream %d quarantined without a reason", r.route.ID)
		}
	}
}

// A destination that only LATER becomes a managed node address is caught at
// emission, not just on write.
func TestScreenStreamSetCatchesNewlyManagedAddress(t *testing.T) {
	in := []caddyapi.StreamRoute{{ID: 7, ListenPort: 5100, UpstreamIP: "198.51.100.20", UpstreamPort: 8080}}

	before := streamguard.New()
	if kept, rejected := screenStreamSet(context.Background(), before, in); len(kept) != 1 || len(rejected) != 0 {
		t.Fatalf("expected the stream to pass before the address was managed, got %d kept", len(kept))
	}

	after := streamguard.New()
	after.Add("198.51.100.20") // the address is now a node
	kept, rejected := screenStreamSet(context.Background(), after, in)
	if len(kept) != 0 || len(rejected) != 1 {
		t.Fatalf("expected the stream to be quarantined once its target became a node, got %d kept", len(kept))
	}
}

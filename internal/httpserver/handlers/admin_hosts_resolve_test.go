package handlers

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/streamguard"
)

func resolveTestInfra(t *testing.T) *streamguard.InfraTargets {
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

// A panel-side resolution failure is not an authorisation: only the route's
// explicit node-side-resolution opt-in tolerates it, and nothing tolerates a
// denied destination.
func TestScreenBackendWithToleranceIsNarrow(t *testing.T) {
	infra := resolveTestInfra(t)
	ctx := context.Background()

	for _, tolerate := range []bool{false, true} {
		if err := screenBackendWith(ctx, infra, "10.66.0.9", 8080, tolerate); err == nil {
			t.Errorf("tolerate=%v: control-plane literal must stay denied", tolerate)
		}
		if err := screenBackendWith(ctx, infra, "10.0.0.5", 2019, tolerate); err == nil {
			t.Errorf("tolerate=%v: node admin API port must stay denied", tolerate)
		}
		if err := screenBackendWith(ctx, infra, "10.0.0.5", 8080, tolerate); err != nil {
			t.Errorf("tolerate=%v: customer origin must stay allowed: %v", tolerate, err)
		}
	}
}

// The refusal has to name the one thing that unblocks the operator, or they
// cannot tell a typo from a name only the node can see.
func TestUnresolvedHint(t *testing.T) {
	err := fmt.Errorf("%w: only-on-the-node", streamguard.ErrUnresolved)
	got := unresolvedHint(err, "fallback")
	if !strings.Contains(got, "resolved on the node") {
		t.Errorf("unresolved error must point at the per-route opt-in, got %q", got)
	}
	if got := unresolvedHint(fmt.Errorf("blocked"), "fallback"); got != "fallback" {
		t.Errorf("other errors keep their message, got %q", got)
	}
}

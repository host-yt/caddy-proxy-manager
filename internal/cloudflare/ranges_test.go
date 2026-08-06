package cloudflare

import (
	"net"
	"testing"
)

func TestEdgeRangesParse(t *testing.T) {
	cidrs := EdgeCIDRs()
	if len(cidrs) == 0 {
		t.Fatal("no Cloudflare edge ranges")
	}
	// A silently dropped bad CIDR would shrink the trust list and make the
	// panel reject real Cloudflare peers, so parity is the actual invariant.
	if got, want := len(EdgeIPNets()), len(cidrs); got != want {
		t.Fatalf("parsed %d ranges from %d CIDRs - one failed to parse", got, want)
	}
	for _, s := range cidrs {
		if _, _, err := net.ParseCIDR(s); err != nil {
			t.Errorf("invalid CIDR %q: %v", s, err)
		}
	}
}

func TestEdgeCIDRsReturnsCopy(t *testing.T) {
	a := EdgeCIDRs()
	a[0] = "0.0.0.0/0"
	if EdgeCIDRs()[0] == "0.0.0.0/0" {
		t.Fatal("EdgeCIDRs must not expose the backing array")
	}
}

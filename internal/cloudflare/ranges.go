package cloudflare

import "net"

// edgeCIDRs — IP ranges Cloudflare publishes as their edge POPs
// (https://www.cloudflare.com/ips/). Refreshed manually here; the CF list
// seldom changes. Bundled instead of fetched at runtime to avoid an SSRF
// dependency loop.
var edgeCIDRs = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
	"103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
	"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
	"198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
	"2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
	"2c0f:f248::/32",
}

var edgeIPNets = mustParseCIDRs(edgeCIDRs)

// EdgeCIDRs returns a copy of the Cloudflare edge ranges as CIDR strings,
// for feeding Caddy's trusted_proxies on the nodes.
func EdgeCIDRs() []string {
	out := make([]string, len(edgeCIDRs))
	copy(out, edgeCIDRs)
	return out
}

// EdgeIPNets returns the parsed edge ranges, for in-panel peer checks.
func EdgeIPNets() []*net.IPNet { return edgeIPNets }

func mustParseCIDRs(in []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(in))
	for _, s := range in {
		if _, ipn, err := net.ParseCIDR(s); err == nil {
			out = append(out, ipn)
		}
	}
	return out
}

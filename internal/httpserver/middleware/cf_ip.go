package middleware

import (
	"net"
	"net/http"
	"strings"
)

// TrustFunc returns true when this request comes from Cloudflare and we
// should honour CF-Connecting-IP. The decision is owned by the
// cloudflare package (admin toggles a setting).
type TrustFunc func() bool

// cloudflareIPv4 / cloudflareIPv6 — IP ranges Cloudflare publishes as their
// edge POPs (https://www.cloudflare.com/ips/). Refreshed manually here;
// CFlist seldom changes — when it does, bump these slices. Bundled
// instead of fetched at runtime to avoid an SSRF dependency loop.
var cloudflareCIDRs = mustParseCIDRs([]string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
	"103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
	"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
	"198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
	"2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
	"2c0f:f248::/32",
})

func mustParseCIDRs(in []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(in))
	for _, s := range in {
		_, ipn, err := net.ParseCIDR(s)
		if err == nil {
			out = append(out, ipn)
		}
	}
	return out
}

// fromCloudflare returns true when the immediate peer's IP falls in a
// published Cloudflare edge range. Without this check, the prior code
// would accept ANY CF-Connecting-IP header so long as the admin had the
// "trust CF" toggle on — meaning a direct attacker could spoof their
// client IP for audit logs / brute-force lockouts.
func fromCloudflare(remoteAddr string) bool {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, cidr := range cloudflareCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// CloudflareIP rewrites r.RemoteAddr from the CF-Connecting-IP header
// when trust is enabled AND the request actually came from a Cloudflare
// edge IP. Should run AFTER chimw.RealIP so the chained middleware sees
// the right IP.
func CloudflareIP(trust TrustFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if trust != nil && trust() && fromCloudflare(r.RemoteAddr) {
				if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
					r.RemoteAddr = ip
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

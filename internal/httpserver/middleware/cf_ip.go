package middleware

import (
	"net"
	"net/http"
	"strings"

	"github.com/host-yt/caddy-proxy-manager/internal/cloudflare"
)

// TrustFunc returns true when this request comes from Cloudflare and we
// should honour CF-Connecting-IP. The decision is owned by the
// cloudflare package (admin toggles a setting).
type TrustFunc func() bool

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
	for _, cidr := range cloudflare.EdgeIPNets() {
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

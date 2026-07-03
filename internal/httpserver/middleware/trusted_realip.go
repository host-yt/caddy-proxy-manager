package middleware

import (
	"net"
	"net/http"
	"strings"
)

// TrustedRealIP rewrites r.RemoteAddr from X-Forwarded-For / X-Real-IP /
// True-Client-IP only when the immediate peer is in `trustedCIDRs`. This
// replaces chi's stock RealIP, which honors those headers unconditionally
// - i.e. lets any direct caller spoof their IP for audit + brute-force
// lockouts when the panel is exposed without a reverse proxy.
//
// Pass the parsed APP_TRUSTED_PROXIES list. Empty list = no proxy trusted,
// headers are ignored regardless of where the request came from. This is
// the safer default: operators must explicitly opt-in by listing their
// edge proxy CIDR.
//
// For XFF specifically, only the LEFT-MOST entry that itself comes from
// outside the trusted set is used - preventing a chain of trusted proxies
// from concealing a downstream spoof.
func TrustedRealIP(trustedCIDRs []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			peer := stripPort(r.RemoteAddr)
			if !inAnyCIDR(peer, trustedCIDRs) {
				// Untrusted peer must not dictate the host: portal resolves the
				// protected host from X-Forwarded-Host. Strip only when a trusted
				// list exists, else unconfigured setups behind Caddy break.
				if len(trustedCIDRs) > 0 {
					r.Header.Del("X-Forwarded-Host")
				}
				next.ServeHTTP(w, r)
				return
			}
			if ip := strings.TrimSpace(r.Header.Get("True-Client-IP")); ip != "" {
				if net.ParseIP(ip) != nil {
					r.RemoteAddr = ip
					next.ServeHTTP(w, r)
					return
				}
			}
			if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
				if net.ParseIP(ip) != nil {
					r.RemoteAddr = ip
					next.ServeHTTP(w, r)
					return
				}
			}
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				// Walk right-to-left: first non-trusted hop is the originator.
				parts := strings.Split(xff, ",")
				for i := len(parts) - 1; i >= 0; i-- {
					cand := strings.TrimSpace(parts[i])
					if cand == "" {
						continue
					}
					if net.ParseIP(cand) == nil {
						continue
					}
					if inAnyCIDR(cand, trustedCIDRs) {
						continue
					}
					r.RemoteAddr = cand
					break
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ParseCIDRList parses a list of CIDR strings into []*net.IPNet. Invalid
// entries are silently skipped (config-load logging is the caller's job).
func ParseCIDRList(in []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		// Allow bare IPs ("10.0.0.5") as /32 or /128.
		if !strings.Contains(s, "/") {
			if ip := net.ParseIP(s); ip != nil {
				if ip.To4() != nil {
					s += "/32"
				} else {
					s += "/128"
				}
			}
		}
		if _, ipn, err := net.ParseCIDR(s); err == nil {
			out = append(out, ipn)
		}
	}
	return out
}

func inAnyCIDR(host string, cidrs []*net.IPNet) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, c := range cidrs {
		if c.Contains(ip) {
			return true
		}
	}
	return false
}

func stripPort(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return strings.Trim(addr, "[]")
}

// IPAllowList wraps `next` so it only fires when the peer's IP matches one
// of the supplied CIDRs. An empty `allow` slice keeps the handler open -
// callers should pass a non-empty list to actually restrict access.
func IPAllowList(allow []*net.IPNet, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(allow) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		if inAnyCIDR(stripPort(r.RemoteAddr), allow) {
			next.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
}

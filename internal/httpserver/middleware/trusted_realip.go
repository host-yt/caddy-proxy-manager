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
// HPG-SEC-005: a trusted peer is trusted to relay XFF correctly, not to
// hand us an arbitrary client-set header verbatim. X-Forwarded-For is an
// append-only chain a well-behaved proxy (including our own bundled Caddy)
// grows by adding the address it actually saw, so walking it right-to-left
// past every trusted hop yields a value the client cannot dictate even
// though the header itself started life client-settable. True-Client-IP and
// X-Real-IP are single-value headers with no such chain - a client sets the
// whole thing - so they are honored only for the specific header names the
// operator names in `trustHeaders` (nil/empty = none), the same "model the
// proxy chain explicitly" approach CloudflareIP already uses for
// CF-Connecting-IP (see cf_ip.go): a real edge proxy that overwrites one of
// these before forwarding is opted in by name, nothing is trusted blindly.
func TrustedRealIP(trustedCIDRs []*net.IPNet, trustHeaders map[string]bool) func(http.Handler) http.Handler {
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
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				// Walk right-to-left: the first hop (from the right) that is
				// NOT itself a trusted proxy is the verified originator - a
				// chain of trusted proxies cannot conceal a downstream spoof.
				parts := strings.Split(xff, ",")
				for i := len(parts) - 1; i >= 0; i-- {
					cand := strings.TrimSpace(parts[i])
					if cand == "" || net.ParseIP(cand) == nil {
						continue
					}
					if inAnyCIDR(cand, trustedCIDRs) {
						continue
					}
					r.RemoteAddr = cand
					next.ServeHTTP(w, r)
					return
				}
			}
			if trustHeaders["True-Client-IP"] {
				if ip := strings.TrimSpace(r.Header.Get("True-Client-IP")); ip != "" && net.ParseIP(ip) != nil {
					r.RemoteAddr = ip
					next.ServeHTTP(w, r)
					return
				}
			}
			if trustHeaders["X-Real-IP"] {
				if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" && net.ParseIP(ip) != nil {
					r.RemoteAddr = ip
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ParseTrustHeaders builds the trustHeaders set TrustedRealIP takes from the
// operator-supplied header name list (env APP_TRUST_REALIP_HEADERS). Only
// True-Client-IP and X-Real-IP are recognized; anything else is ignored -
// there is no handler for a third one to enable.
func ParseTrustHeaders(names []string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, n := range names {
		switch {
		case strings.EqualFold(strings.TrimSpace(n), "True-Client-IP"):
			out["True-Client-IP"] = true
		case strings.EqualFold(strings.TrimSpace(n), "X-Real-IP"):
			out["X-Real-IP"] = true
		}
	}
	return out
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

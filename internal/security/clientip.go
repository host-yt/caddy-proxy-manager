package security

import (
	"net"
	"net/http"
	"strings"
)

// ClientIP returns the best-effort client IP for audit / rate-limit
// attribution.
//
// The HTTP server chain runs `chimw.RealIP` first, which rewrites
// `r.RemoteAddr` from `X-Forwarded-For` ONLY when the immediate peer is
// already in a private/loopback range - i.e. when the panel sits behind a
// reverse proxy on the same host or LAN. Then our own
// `middleware.CloudflareIP` overwrites again if the operator has opted into
// trusting `CF-Connecting-IP`. By the time handlers run, `r.RemoteAddr`
// already carries the trustable client IP.
//
// This helper is the SINGLE place handlers and audit consult. It does NOT
// parse `X-Forwarded-For` directly - that was the bug the audit flagged
// (any client could spoof their IP via header injection when the panel was
// exposed without a proxy).
func ClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	host := r.RemoteAddr
	if host == "" {
		return ""
	}
	// Strip :port if present. net.SplitHostPort handles IPv6 bracketed too.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	// Tolerate raw IPv6 with surrounding brackets that some proxies write.
	host = strings.Trim(host, "[]")
	return host
}

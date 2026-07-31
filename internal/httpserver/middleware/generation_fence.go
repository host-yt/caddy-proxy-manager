package middleware

import (
	"net/http"
	"strings"
)

// fenceExemptPaths stay reachable while fenced so orchestrators can still read
// probes and scrape the draining replica.
var fenceExemptPaths = []string{"/healthz", "/readyz", "/metrics"}

// GenerationFence stops serving as soon as a newer session generation owns the
// fleet: this binary reads Restricted/Epoch more permissively, and readiness
// alone would leave existing keep-alive/HTTP2 connections authenticated here
// until an external controller finished draining. fenced is a cached read - no
// Redis round-trip per request.
func GenerationFence(fenced func() bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if fenced == nil || fenceExempt(r.URL.Path) || !fenced() {
				next.ServeHTTP(w, r)
				return
			}
			// h1 only: "Connection" is an illegal HTTP/2 header, and h2 streams
			// are torn down by the graceful shutdown the fence also triggers.
			if r.ProtoMajor < 2 {
				w.Header().Set("Connection", "close")
			}
			w.Header().Set("Retry-After", "5")
			http.Error(w, "draining: a newer control-plane generation owns this fleet", http.StatusServiceUnavailable)
		})
	}
}

func fenceExempt(path string) bool {
	for _, p := range fenceExemptPaths {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

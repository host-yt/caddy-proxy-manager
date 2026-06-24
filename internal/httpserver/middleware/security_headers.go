package middleware

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
)

type cspNonceKey int

const cspNonceCtxKey cspNonceKey = 1

// CSPNonce returns the per-request CSP nonce for use in inline script/style
// blocks. Templates embed it via `nonce="{{.CSPNonce}}"`.
func CSPNonce(ctx context.Context) string {
	v, _ := ctx.Value(cspNonceCtxKey).(string)
	return v
}

// SecurityHeaders sets defensive HTTP headers on every response and
// generates a per-request CSP nonce.
//
// CSP policy:
//   - default-src 'self'
//   - script-src 'self' 'nonce-<n>' (no 'unsafe-inline'; legacy CDN hosts
//     removed - Tailwind/Alpine/Chart.js must be served from the panel
//     itself or with a matching nonce)
//   - style-src 'self' 'nonce-<n>' https://rsms.me
//   - third-party allowlist stays narrow for Turnstile.
//
// Existing templates that still ship inline <script> blocks must include
// `nonce="{{.CSPNonce}}"` (templates already expose the value via the
// base data struct).
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nb := make([]byte, 16)
		_, _ = rand.Read(nb)
		nonce := base64.RawStdEncoding.EncodeToString(nb)

		ctx := context.WithValue(r.Context(), cspNonceCtxKey, nonce)
		r = r.WithContext(ctx)

		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		h.Set("Content-Security-Policy", strictCSP(nonce))
		next.ServeHTTP(w, r)
	})
}

// strictCSP intentionally OMITS 'strict-dynamic' (the v1 audit flagged
// it as contradicting the host allowlist).
//
// style-src keeps 'unsafe-inline' because Tailwind's CDN runtime injects
// generated CSS via DOM at runtime - those <style> tags have no nonce
// and CSP would otherwise block all panel styling. style-src unsafe-inline
// permits CSS manipulation, not script execution; the script-src stays
// strict (nonce-only inline, explicit host allowlist for CDNs).
//
// When a fully static Tailwind build replaces the CDN runtime, drop
// 'unsafe-inline' from style-src and require nonces only.
func strictCSP(nonce string) string {
	return "default-src 'self'; " +
		// Everything is now self-hosted: Tailwind at /static/css/tailwind.css,
		// Chart.js at /static/js/chart.umd.min.js, Inter font at
		// /static/fonts/. Only challenges.cloudflare.com remains for Turnstile.
		"script-src 'self' 'nonce-" + nonce + "' https://challenges.cloudflare.com; " +
		"style-src 'self' 'unsafe-inline'; " +
		"font-src 'self'; " +
		// https: lets branding logo/favicon come from any HTTPS CDN.
		"img-src 'self' https: data: blob:; " +
		"connect-src 'self' https://challenges.cloudflare.com; " +
		"frame-src https://challenges.cloudflare.com; " +
		"frame-ancestors 'none'; " +
		"base-uri 'self'; " +
		"form-action 'self'; " +
		"object-src 'none'"
}

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
//   - style-src 'self' 'unsafe-inline' (see strictCSP for why nonce-only
//     isn't safe to ship yet)
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
// style-src still keeps 'unsafe-inline'. Tailwind is now self-hosted (the
// CDN-runtime justification is stale), but ~60+ templates under
// internal/view use inline style="..." attributes and several ship
// unnoned <style> blocks (e.g. admin/_layout.html.tmpl, app/_layout.html.tmpl).
// Dropping unsafe-inline here today would blank-page most of the UI.
// TODO: migrate those templates to nonce="{{.CSPNonce}}" / static CSS
// classes, then drop unsafe-inline. unsafe-inline on style-src permits CSS
// manipulation only, not script execution; script-src stays nonce-strict.
func strictCSP(nonce string) string {
	// CAPTCHA vendor origins (login widget): Cloudflare Turnstile, hCaptcha,
	// Google reCAPTCHA. Only loaded when an admin selects that provider.
	const captchaScript = " https://challenges.cloudflare.com https://*.hcaptcha.com https://www.google.com https://www.gstatic.com"
	const captchaFrame = " https://challenges.cloudflare.com https://*.hcaptcha.com https://www.google.com"
	return "default-src 'self'; " +
		// Everything is now self-hosted: Tailwind at /static/css/tailwind.css,
		// Chart.js at /static/js/chart.umd.min.js, Inter font at /static/fonts/.
		// Remote hosts below are CAPTCHA vendor widgets only.
		"script-src 'self' 'nonce-" + nonce + "'" + captchaScript + "; " +
		"style-src 'self' 'unsafe-inline'; " +
		"font-src 'self'; " +
		// https: stays: branding.logo_url_* / error_logo_url / geo_block_logo_url
		// are free-text URL fields (admin_branding.go), not uploaded files, so
		// logos can legitimately live on an arbitrary external HTTPS host.
		"img-src 'self' https: data: blob:; " +
		"connect-src 'self'" + captchaFrame + "; " +
		"frame-src" + captchaFrame + "; " +
		"frame-ancestors 'none'; " +
		"base-uri 'self'; " +
		"form-action 'self'; " +
		"object-src 'none'"
}

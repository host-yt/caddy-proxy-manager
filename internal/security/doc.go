// Package security holds cross-cutting security helpers used by HTTP
// handlers and audit:
//
//   - ClientIP: the single trusted source for the request's client IP,
//     reading r.RemoteAddr after chimw.RealIP + the Cloudflare-IP middleware
//     have already done their job. Handlers must NOT parse
//     X-Forwarded-For themselves.
//
// Other concerns live in their own packages:
//   - CSRF, rate-limit, session, security headers → internal/httpserver/middleware
//   - At-rest secret encryption (AES-256-GCM via HKDF(APP_SECRET)) →
//     internal/installstate
//   - Domain validation → internal/domain/routes (validDomain)
package security

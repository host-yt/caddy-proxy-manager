package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// VerifyCSRF enforces a per-session CSRF token on state-changing requests.
//
// Skips:
//   - GET, HEAD, OPTIONS, TRACE
//   - Requests with no session (unauthenticated)
//   - Install wizard POSTs (bootstrapping before sessions exist)
//   - /api/* endpoints (use bearer-token auth, no cookie)
//
// Cookie-authed POST/PUT/DELETE (including application/json) MUST send
// X-CSRF-Token or csrf_token matching session.CSRFToken. JSON content-
// type is no longer an exemption - fetch() with credentials:include can
// post JSON cross-origin without preflight when the body is a SimpleType.
func VerifyCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/install/") || strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		// Login POST: no session yet, no CSRF. Same-origin + SameSite=Lax
		// cookies + the rate limit on the login form covers this.
		if r.URL.Path == "/auth/login" || r.URL.Path == "/auth/forgot" || strings.HasPrefix(r.URL.Path, "/auth/reset") {
			next.ServeHTTP(w, r)
			return
		}
		// Built-in portal endpoints run on the protected host, not the panel
		// origin, so there is no panel session/CSRF token to present. The
		// portal enforces its OWN double-submit CSRF token on login/2FA POSTs
		// (see PortalHandlers.verifyPortalCSRF) plus SameSite=Lax + lockout.
		if strings.HasPrefix(r.URL.Path, "/hpg-portal/") {
			next.ServeHTTP(w, r)
			return
		}

		sess := SessionFromContext(r.Context())
		if sess == nil {
			next.ServeHTTP(w, r)
			return
		}
		// Parse form so r.FormValue works; cap body to 8 MiB.
		r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
		_ = r.ParseForm()

		got := r.Header.Get("X-CSRF-Token")
		if got == "" {
			got = r.FormValue("csrf_token")
		}
		// Constant-time compare keeps timing oracles from leaking partial token bytes.
		if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(sess.CSRFToken)) != 1 {
			http.Error(w, "CSRF token mismatch", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

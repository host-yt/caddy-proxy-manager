package middleware

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
)

// InstallGuard protects state-changing /install/* endpoints while the wizard
// is still active. Behaviour:
//
//   - If INSTALL_TOKEN env var is set, every state-changing request must
//     present a matching `install_token` form field, `X-Install-Token`
//     header, or `?install_token=…` query value. Non-matching → 403.
//   - If INSTALL_TOKEN is empty *and* the request RemoteAddr is loopback,
//     the request is allowed (operator did `ssh + port-forward + 127.0.0.1`).
//   - Otherwise (no token, request not loopback) → 403 with instructions.
//
// Once the wizard locks itself (`installed=true`), `installRedirectMiddleware`
// in server.go redirects /install/* to /auth/login, so this guard is moot.
func InstallGuard(installed func() bool, expectedToken string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if installed() {
				// Wizard is locked. Inert reads may pass, but any
				// state-changing request after install is a re-entry attempt
				// (POST /install/admin would mint a rogue super_admin,
				// /install/db would repoint the DB, /install/caddy would
				// register a rogue node) - refuse it. Defense-in-depth with
				// the per-handler IsInstalled checks.
				switch r.Method {
				case http.MethodGet, http.MethodHead, http.MethodOptions:
					next.ServeHTTP(w, r)
				default:
					http.NotFound(w, r)
				}
				return
			}
			// Only gate state-changing methods. GET /install (wizard pages)
			// are inert and rendered by the wizard handler itself.
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				next.ServeHTTP(w, r)
				return
			}
			if expectedToken != "" {
				if installTokenOK(r, expectedToken) {
					next.ServeHTTP(w, r)
					return
				}
				http.Error(w, "install token required (set INSTALL_TOKEN env, then submit it in the form)", http.StatusForbidden)
				return
			}
			// Loopback RemoteAddr only means "local operator" when the request did
			// NOT arrive through a proxy. If the panel co-resides with the fronting
			// proxy and APP_TRUSTED_PROXIES is unset, every proxied request also
			// presents RemoteAddr=127.0.0.1 - so a bare loopback check would let
			// external POSTs to /install/* through. Forwarded headers betray that.
			if isLoopback(r.RemoteAddr) && !viaProxy(r) {
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w,
				"installer is closed to non-loopback (or proxied) requests until INSTALL_TOKEN is set. "+
					"Either set INSTALL_TOKEN in the panel env and pass it as the install_token field, "+
					"or run the wizard from a direct loopback address (e.g. SSH port-forward, no proxy).",
				http.StatusForbidden)
		})
	}
}

func installTokenOK(r *http.Request, expected string) bool {
	got := r.Header.Get("X-Install-Token")
	if got == "" {
		got = r.URL.Query().Get("install_token")
	}
	if got == "" {
		_ = r.ParseForm()
		got = r.FormValue("install_token")
	}
	if got == "" {
		// Cookie set by the wizard welcome form once the operator pastes
		// INSTALL_TOKEN once. Cleared automatically when the wizard locks.
		if c, err := r.Cookie("hpg_install_token"); err == nil {
			got = c.Value
		}
	}
	if got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}

// viaProxy reports whether the request carries forwarding headers, i.e. it
// reached us through a reverse proxy. Used to refuse the loopback install
// bypass when RemoteAddr is only loopback because a co-resident proxy
// terminated the real (possibly external) client.
func viaProxy(r *http.Request) bool {
	return r.Header.Get("X-Forwarded-For") != "" ||
		r.Header.Get("X-Real-IP") != "" ||
		r.Header.Get("Forwarded") != ""
}

func isLoopback(remote string) bool {
	host := remote
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		return host == "localhost"
	}
	return ip.IsLoopback()
}

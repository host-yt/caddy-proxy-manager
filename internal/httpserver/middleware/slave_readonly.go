package middleware

import (
	"net/http"
	"path"
	"strings"
)

// slaveWriteExact are the only exact paths a slave accepts writes on: the
// master's sync push plus the session flow, so the read-only UI stays usable.
// Register/forgot/reset are left out on purpose - they write user rows.
var slaveWriteExact = map[string]bool{
	"/internal/sync/push":        true,
	"/internal/access-log":       true,
	"/auth/login":                true,
	"/auth/logout":               true,
	"/auth/end-impersonation":    true,
	"/auth/2fa":                  true,
	"/auth/2fa/send":             true,
	"/auth/sms-otp":              true,
	"/auth/email-otp":            true,
	"/auth/passkey/login/begin":  true,
	"/auth/passkey/login/finish": true,
}

// slaveWritePrefixes: node-agent telemetry (bearer node_token), the
// forward-auth portal (session minting only) and the install wizard, which
// InstallGuard locks once installed.
var slaveWritePrefixes = []string{"/api/node/", "/hpg-portal/", "/install/"}

// SlaveReadOnly makes a slave instance read-only: every method other than
// GET/HEAD/OPTIONS is refused unless the path is on the allowlist above.
// Fail-closed, so new routes (/admin, /app, /api/v1, ...) are blocked by default.
func SlaveReadOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if slaveWriteAllowed(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, "slave mode: read-only", http.StatusForbidden)
	})
}

func slaveWriteAllowed(p string) bool {
	// Unclean paths (dot segments, double slashes) never match a prefix.
	if path.Clean(p) != p {
		return false
	}
	if slaveWriteExact[p] {
		return true
	}
	for _, pre := range slaveWritePrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

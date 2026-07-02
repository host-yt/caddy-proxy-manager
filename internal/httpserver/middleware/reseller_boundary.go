package middleware

import "net/http"

// ResellerAdminBoundary is a DEFAULT-DENY gate for reseller-admins (a session
// carrying a non-zero ResellerID). They may reach only the allow-listed,
// client-scoped surface; every other /admin path (global infra: nodes, settings,
// branding, plans, users, backups, audit, ...) returns 403. Platform
// admins/super_admins (ResellerID==0) pass untouched.
//
// Default-deny is deliberate: a forgotten client-scoped route over-restricts a
// reseller-admin (annoying) instead of leaking global infra (a breach). The
// allow-list grows as the reseller panel adds per-resource ownership checks.
// ResellerID is stamped on the session at login, so this costs no DB lookup.
func ResellerAdminBoundary(allowed []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess := SessionFromContext(r.Context())
			if sess == nil || sess.ResellerID == 0 {
				next.ServeHTTP(w, r) // not a reseller-admin
				return
			}
			if !pathAllowed(r.URL.Path, allowed) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

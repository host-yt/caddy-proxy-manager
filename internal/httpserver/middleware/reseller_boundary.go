package middleware

import "net/http"

// ResellerAdminBoundary is a DEFAULT-DENY gate for every limited admin: a
// reseller-admin (ResellerID != 0) and a client-scoped restricted admin
// (users.is_restricted, Restricted == true). They may reach only the
// allow-listed, client-scoped surface; every other /admin path (global infra:
// nodes, settings, branding, plans, users, backups, audit, ...) returns 403.
// Full platform admins/super_admins pass untouched.
//
// Default-deny is deliberate: a forgotten client-scoped route over-restricts a
// limited admin (annoying) instead of leaking global infra (a breach). The
// allow-list grows as the reseller panel adds per-resource ownership checks.
// Both flags are stamped on the session at login, so this costs no DB lookup.
func ResellerAdminBoundary(allowed []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess := SessionFromContext(r.Context())
			// role=reseller stays confined even with no reseller_id: an orphaned
			// reseller (its row deleted) must never widen into a platform admin.
			if sess == nil || (sess.ResellerID == 0 && !sess.Restricted && sess.Role != "reseller") {
				next.ServeHTTP(w, r) // full platform admin
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

package middleware

import (
	"net/http"
	"strings"
)

// SlaveReadOnly blocks state-mutating methods on /admin/* paths when running
// in slave mode. GET/HEAD/OPTIONS and /internal/sync/push are always allowed.
func SlaveReadOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		m := r.Method
		// Always pass the slave receive endpoint through.
		if p == "/internal/sync/push" {
			next.ServeHTTP(w, r)
			return
		}
		// Block writes on admin paths so the UI still loads but forms fail visibly.
		if strings.HasPrefix(p, "/admin") &&
			(m == http.MethodPost || m == http.MethodPut || m == http.MethodPatch || m == http.MethodDelete) {
			http.Error(w, "slave mode: read-only", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

package middleware

import (
	"net/http"
	"path"
	"strings"
)

// ReadOnlyRole blocks state-changing requests for the named role.
// It is intended for support-style panel access where the same GET surfaces
// are useful, but POST/PUT/PATCH/DELETE mutations must fail closed.
func ReadOnlyRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess := SessionFromContext(r.Context())
			if sess != nil && sess.Role == role && !isSafeMethod(r.Method) {
				http.Error(w, "read-only role", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ReadOnlyRoleAllowList blocks state-changing requests for role and limits its
// safe-method access to exact paths or path.Match-style glob patterns.
func ReadOnlyRoleAllowList(role string, allowed []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess := SessionFromContext(r.Context())
			if sess == nil || sess.Role != role {
				next.ServeHTTP(w, r)
				return
			}
			if !isSafeMethod(r.Method) {
				http.Error(w, "read-only role", http.StatusForbidden)
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

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func pathAllowed(requestPath string, allowed []string) bool {
	for _, pattern := range allowed {
		if ok, _ := path.Match(pattern, requestPath); ok {
			return true
		}
		if strings.HasSuffix(pattern, "*") {
			if strings.HasPrefix(requestPath, strings.TrimSuffix(pattern, "*")) {
				return true
			}
			continue
		}
		if requestPath == pattern {
			return true
		}
	}
	return false
}

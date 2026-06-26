// Package middleware contains HTTP middlewares used by httpserver.
package middleware

import (
	"context"
	"net/http"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
)

type ctxKey int

const sessionCtxKey ctxKey = 1

// LoadSession reads the session cookie (if any) and stores it on context.
// Does NOT enforce auth - that's RequireRole's job.
func LoadSession(sm *auth.Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, err := sm.Load(r.Context(), r)
			if err == nil && sess != nil {
				ctx := context.WithValue(r.Context(), sessionCtxKey, sess)
				// Tag ctx with impersonator info so audit.Write attributes
				// the actor to the admin while still recording the
				// impersonated client in meta.
				if sess.ImpersonatorUserID > 0 {
					ctx = audit.WithImpersonator(ctx, audit.Impersonator{
						AdminUserID:        sess.ImpersonatorUserID,
						ImpersonatedUserID: sess.UserID,
						ImpersonatedEmail:  sess.Email,
					})
				}
				r = r.WithContext(ctx)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SessionFromContext returns the loaded session or nil.
func SessionFromContext(ctx context.Context) *auth.Session {
	v, _ := ctx.Value(sessionCtxKey).(*auth.Session)
	return v
}

// ContextWithSession attaches a session to ctx using the same key SessionFromContext reads.
// Exported so other packages (e.g. handler tests) can build authenticated requests.
func ContextWithSession(ctx context.Context, sess *auth.Session) context.Context {
	return context.WithValue(ctx, sessionCtxKey, sess)
}

// RequireRole forces a logged-in user whose role is in allowed.
// Unauthenticated -> redirect to /auth/login (for browser routes).
// Wrong role      -> 403.
func RequireRole(allowed ...string) func(http.Handler) http.Handler {
	allowedSet := map[string]struct{}{}
	for _, r := range allowed {
		allowedSet[r] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess := SessionFromContext(r.Context())
			if sess == nil {
				http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
				return
			}
			if _, ok := allowedSet[sess.Role]; !ok {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

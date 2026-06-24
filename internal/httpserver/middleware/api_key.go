package middleware

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"time"

	"github.com/hostyt/proxy-gateway/internal/auth"
)

type apiKeyCtxKey int

const apiCallerKey apiKeyCtxKey = 1

// APICaller is the resolved authenticated principal for an API request.
type APICaller struct {
	UserID int64
	Role   string
}

// APIKeyAuth verifies the `Authorization: Bearer hpg_...` header and
// attaches an APICaller to the context. 401 on missing/invalid.
//
// Caps every JSON request body at 1 MiB (API surface accepts small
// payloads only - services/routes/nodes JSON is <1 KiB in practice).
// Without this cap a single bearer-authed call could pin memory.
func APIKeyAuth(db func() *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			if !strings.HasPrefix(h, "Bearer ") {
				writeJSONErr(w, http.StatusUnauthorized, "missing bearer token")
				return
			}
			token := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
			d := db()
			if d == nil {
				writeJSONErr(w, http.StatusServiceUnavailable, "db not ready")
				return
			}
			// Bound the auth DB work: a slow/saturated DB must not pin an API
			// request for the full request timeout (chi 30s) just to verify a
			// bearer. 3s is ample for two indexed lookups.
			authCtx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			defer cancel()
			uid, role, err := auth.VerifyAPIKey(authCtx, d, token)
			if err != nil {
				writeJSONErr(w, http.StatusUnauthorized, "invalid token")
				return
			}
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			}
			// Re-fetch role/is_active from DB on each request: if an admin
			// demoted the underlying user (role change or is_active = 0),
			// existing sessions/tokens must immediately stop working
			// rather than waiting for the bearer to expire (security
			// review P2: stale-role).
			var stillActive bool
			var freshRole string
			if err := d.QueryRowContext(authCtx,
				"SELECT role, is_active FROM users WHERE id = ?", uid,
			).Scan(&freshRole, &stillActive); err != nil || !stillActive {
				writeJSONErr(w, http.StatusUnauthorized, "user disabled")
				return
			}
			role = freshRole
			ctx := context.WithValue(r.Context(), apiCallerKey, &APICaller{UserID: uid, Role: role})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// CallerFromContext returns the API caller or nil.
func CallerFromContext(ctx context.Context) *APICaller {
	v, _ := ctx.Value(apiCallerKey).(*APICaller)
	return v
}

func writeJSONErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + msg + `"}`))
}

package middleware

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/security"
)

type apiKeyCtxKey int

const apiCallerKey apiKeyCtxKey = 1

// APICaller is the resolved authenticated principal for an API request.
type APICaller struct {
	UserID int64
	KeyID  int64
	Role   string
	// Scopes carried by the API key. Empty means the key is unscoped and has
	// full access (back-compat: keys issued before scope enforcement).
	Scopes []string
}

// HasScope reports whether the caller may use the given scope. An unscoped
// key (no scopes recorded) is treated as full access for back-compat.
func (c *APICaller) HasScope(want ...string) bool {
	if c == nil {
		return false
	}
	if len(c.Scopes) == 0 {
		return true
	}
	for _, s := range c.Scopes {
		for _, w := range want {
			if s == w {
				return true
			}
		}
	}
	return false
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
			clientIP := security.ClientIP(r)
			uid, keyID, role, scopes, err := auth.VerifyAPIKey(authCtx, d, token, clientIP)
			if err != nil {
				// Audit failed attempts for hpg_-prefixed tokens only; garbage
				// or absent headers are too noisy to be actionable.
				if strings.HasPrefix(token, "hpg_") && len(token) > 12 {
					prefix := token[4:12] // 8-char prefix after "hpg_"
					audit.Write(authCtx, d, nil, r, audit.Entry{
						ActorType: audit.ActorAPI,
						Action:    "api_key.auth_failure",
						Entity:    "api_key",
						Meta:      map[string]any{"prefix": prefix},
					})
				}
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
			ctx := context.WithValue(r.Context(), apiCallerKey, &APICaller{UserID: uid, KeyID: keyID, Role: role, Scopes: parseScopes(scopes)})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// CallerFromContext returns the API caller or nil.
func CallerFromContext(ctx context.Context) *APICaller {
	v, _ := ctx.Value(apiCallerKey).(*APICaller)
	return v
}

// ContextWithAPICaller attaches an APICaller (used by tests and any handler that
// needs to synthesize a caller). Production requests get theirs from APIKeyAuth.
func ContextWithAPICaller(ctx context.Context, c *APICaller) context.Context {
	return context.WithValue(ctx, apiCallerKey, c)
}

// parseScopes splits the stored comma-separated scope list, trimming blanks.
func parseScopes(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// RequireScope enforces that the API key carries at least one of the given
// scopes (security review API-01: scopes were stored but never enforced).
// Must sit behind APIKeyAuth. An unscoped key passes (see APICaller.HasScope).
func RequireScope(want ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !CallerFromContext(r.Context()).HasScope(want...) {
				writeJSONErr(w, http.StatusForbidden, "api key missing required scope")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAdminScope gates admin-domain resources (clients, plans,
// provisioning): safe methods need admin:read or admin:write, mutations need
// admin:write.
func RequireAdminScope() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c := CallerFromContext(r.Context())
			ok := false
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				ok = c.HasScope("admin:read", "admin:write")
			default:
				ok = c.HasScope("admin:write")
			}
			if !ok {
				writeJSONErr(w, http.StatusForbidden, "api key missing required scope")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func writeJSONErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{msg})
}

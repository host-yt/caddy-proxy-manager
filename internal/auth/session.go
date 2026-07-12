package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Session is the server-side record keyed by a random session ID.
//
// During admin impersonation, UserID/Email/Role/ClientID reflect the
// impersonated *client* (so middleware role gates and per-client
// queries Just Work), while ImpersonatorUserID/ImpersonatorEmail carry
// the original admin's identity for accountability. Audit writes
// attribute the actor to ImpersonatorUserID when set and stamp the
// impersonated user into meta - see internal/audit.
type Session struct {
	UserID             int64     `json:"user_id"`
	Email              string    `json:"email"`
	Role               string    `json:"role"`
	ClientID           int64     `json:"client_id,omitempty"`
	// ResellerID is set for a reseller-admin (a role=admin user tied to a
	// reseller); 0 = platform admin / non-reseller. Stamped at login so the
	// reseller-admin route boundary needs no per-request DB lookup.
	ResellerID         int64     `json:"reseller_id,omitempty"`
	CSRFToken          string    `json:"csrf"`
	CreatedAt          time.Time `json:"created_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	ImpersonatorUserID int64     `json:"impersonator_user_id,omitempty"`
	ImpersonatorEmail  string    `json:"impersonator_email,omitempty"`
}

// IsImpersonating reports whether the session is an admin acting as a client.
func (s *Session) IsImpersonating() bool { return s != nil && s.ImpersonatorUserID > 0 }

// Manager creates, reads, and revokes sessions in Redis.
type Manager struct {
	rdb        *redis.Client
	cookieName string
	secure     bool
	sameSite   http.SameSite
	ttl        time.Duration
}

func NewSessionManager(rdb *redis.Client, cookieName string, secure bool, sameSite string, ttl time.Duration) *Manager {
	ss := http.SameSiteLaxMode
	switch sameSite {
	case "strict":
		ss = http.SameSiteStrictMode
	case "none":
		ss = http.SameSiteNoneMode
	}
	return &Manager{rdb: rdb, cookieName: cookieName, secure: secure, sameSite: ss, ttl: ttl}
}

const sessionKeyPrefix = "hpg:sess:"

// CookieSecure exposes the configured Secure flag for callers that issue
// companion short-lived cookies (e.g. pending-2fa).
func (m *Manager) CookieSecure() bool { return m.secure }

// SecureForRequest returns the effective Secure value for a cookie written in
// response to r. Secure is kept only when the request actually arrived over a
// secure context; otherwise we must not set it. Browsers silently drop a
// Secure cookie sent over plain HTTP (e.g. first-run access via http://<IP>),
// which otherwise causes an infinite login loop. Never upgrades: if the config
// disables Secure it stays off.
func (m *Manager) SecureForRequest(r *http.Request) bool {
	return m.secure && requestIsHTTPS(r)
}

// requestIsHTTPS reports whether r reached us over TLS, either directly or via
// a fronting proxy (Caddy) that set X-Forwarded-Proto. A spoofed header on a
// plain-HTTP request only makes that same request's cookie fail to set, so
// this is not a trust boundary for us.
func requestIsHTTPS(r *http.Request) bool {
	if r == nil {
		return true // no request context: fall back to configured default
	}
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// Create stores a new session in Redis and writes the cookie. resellerID is
// non-zero only for a reseller-admin.
func (m *Manager) Create(ctx context.Context, w http.ResponseWriter, r *http.Request, userID int64, email, role string, clientID, resellerID int64) (*Session, error) {
	return m.CreateImpersonated(ctx, w, r, userID, email, role, clientID, resellerID, 0, "")
}

// CreateImpersonated mints a session whose effective identity is the
// target client (userID/email/role/clientID) but which carries the
// admin's id/email in ImpersonatorUserID for audit accountability.
// Pass impersonatorID=0 for a normal login.
func (m *Manager) CreateImpersonated(ctx context.Context, w http.ResponseWriter, r *http.Request, userID int64, email, role string, clientID, resellerID, impersonatorID int64, impersonatorEmail string) (*Session, error) {
	id, err := randomID(32)
	if err != nil {
		return nil, err
	}
	csrf, err := randomID(16)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	s := &Session{
		UserID:             userID,
		Email:              email,
		Role:               role,
		ClientID:           clientID,
		ResellerID:         resellerID,
		CSRFToken:          csrf,
		CreatedAt:          now,
		ExpiresAt:          now.Add(m.ttl),
		ImpersonatorUserID: impersonatorID,
		ImpersonatorEmail:  impersonatorEmail,
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	if err := m.rdb.Set(ctx, sessionKeyPrefix+id, b, m.ttl).Err(); err != nil {
		return nil, fmt.Errorf("redis set: %w", err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.SecureForRequest(r),
		SameSite: m.sameSite,
		Expires:  s.ExpiresAt,
	})
	return s, nil
}

// Load reads a session by request cookie. Returns (nil, nil) when missing.
func (m *Manager) Load(ctx context.Context, r *http.Request) (*Session, error) {
	c, err := r.Cookie(m.cookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// Bound the Redis read: a slow/blippy Redis must not pin every
	// authenticated request for the full HTTP request timeout. On timeout
	// we treat it as no session (graceful redirect to login) rather than
	// hanging the whole page.
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	b, err := m.rdb.Get(ctx, sessionKeyPrefix+c.Value).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("redis get: %w", err)
	}
	var s Session
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// DestroyAllForUser scans every active session in Redis and deletes the
// ones owned by `userID`. Best-effort: a Redis SCAN cursor that misses a
// key inserted concurrently is fine - the worst case is a one-request
// window for an attacker. Intended for password-reset / disable-user.
//
// Returns the count of sessions actually deleted. No cookie is cleared
// because the caller is not necessarily the same browser that owns the
// session being killed.
func (m *Manager) DestroyAllForUser(ctx context.Context, userID int64) (int, error) {
	if m == nil || m.rdb == nil {
		return 0, nil
	}
	var (
		cursor uint64
		killed int
	)
	for {
		keys, next, err := m.rdb.Scan(ctx, cursor, sessionKeyPrefix+"*", 200).Result()
		if err != nil {
			return killed, err
		}
		for _, k := range keys {
			b, err := m.rdb.Get(ctx, k).Bytes()
			if err != nil {
				continue
			}
			var s Session
			if json.Unmarshal(b, &s) != nil {
				continue
			}
			if s.UserID == userID {
				_ = m.rdb.Del(ctx, k).Err()
				killed++
			}
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return killed, nil
}

// Destroy removes the session and clears the cookie.
func (m *Manager) Destroy(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(m.cookieName)
	if err == nil {
		_ = m.rdb.Del(ctx, sessionKeyPrefix+c.Value).Err()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   m.SecureForRequest(r),
		SameSite: m.sameSite,
		MaxAge:   -1,
	})
}

func randomID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

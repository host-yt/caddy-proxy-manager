package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
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
	// Restricted mirrors users.is_restricted: a client-scoped admin with no
	// reseller. Same default-deny route boundary as a reseller-admin.
	Restricted         bool      `json:"restricted,omitempty"`
	// Epoch is users.auth_epoch at mint time; Load rejects the session once
	// the stored epoch moves (role/scope/password/active change or delete).
	Epoch              int64     `json:"ep"`
	// ImpersonatorEpoch does the same for the admin behind an impersonation.
	ImpersonatorEpoch  int64     `json:"imp_ep,omitempty"`
	// Ver is the session schema version. Load rejects anything below
	// sessionSchemaVer so a pre-Restricted session cannot fail open.
	Ver                int       `json:"v,omitempty"`
	CSRFToken          string    `json:"csrf"`
	CreatedAt          time.Time `json:"created_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	ImpersonatorUserID int64     `json:"impersonator_user_id,omitempty"`
	ImpersonatorEmail  string    `json:"impersonator_email,omitempty"`
}

// IsImpersonating reports whether the session is an admin acting as a client.
func (s *Session) IsImpersonating() bool { return s != nil && s.ImpersonatorUserID > 0 }

// sessionRedis is the Redis subset Manager uses, as an interface so tests can
// inject failures without a live server.
type sessionRedis interface {
	Get(ctx context.Context, key string) *redis.StringCmd
	Set(ctx context.Context, key string, value any, expiration time.Duration) *redis.StatusCmd
	Del(ctx context.Context, keys ...string) *redis.IntCmd
	Scan(ctx context.Context, cursor uint64, match string, count int64) *redis.ScanCmd
}

// isRedisMiss reports a "key not found" as opposed to a transport failure.
func isRedisMiss(err error) bool { return errors.Is(err, redis.Nil) }

// Manager creates, reads, and revokes sessions in Redis.
type Manager struct {
	rdb        sessionRedis
	// db is the authoritative auth-epoch source; nil disables the DB fallback.
	db         *sql.DB
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
	m := &Manager{cookieName: cookieName, secure: secure, sameSite: ss, ttl: ttl}
	// Keep the interface nil for a nil client so the m.rdb == nil guards hold.
	if rdb != nil {
		m.rdb = rdb
	}
	return m
}

// SetEpochSource wires the DB used to verify auth epochs on a cache miss.
func (m *Manager) SetEpochSource(db *sql.DB) { m.db = db }

const sessionKeyPrefix = "hpg:sess:"

// sessionSchemaVer invalidates sessions minted before a security-relevant
// field was added. Bump it whenever a missing field would fail open.
// Ver 2 adds Epoch: a pre-epoch session was minted from claims that were
// never re-verified, so drop them all rather than trust a zero epoch.
const sessionSchemaVer = 2

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

// NewSession describes the identity a session is minted for. Every field must
// come from a fresh users-row read, never from a cached ticket or claim.
// ResellerID is non-zero only for a reseller-admin; during impersonation the
// non-Impersonator fields describe the *target* (never the acting admin).
type NewSession struct {
	UserID     int64
	Email      string
	Role       string
	ClientID   int64
	ResellerID int64
	Restricted bool
	Epoch      int64

	ImpersonatorUserID int64
	ImpersonatorEmail  string
	ImpersonatorEpoch  int64
}

// Create stores a new session in Redis and writes the cookie.
func (m *Manager) Create(ctx context.Context, w http.ResponseWriter, r *http.Request, ns NewSession) (*Session, error) {
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
		UserID:             ns.UserID,
		Email:              ns.Email,
		Role:               ns.Role,
		ClientID:           ns.ClientID,
		ResellerID:         ns.ResellerID,
		Restricted:         ns.Restricted,
		Epoch:              ns.Epoch,
		ImpersonatorEpoch:  ns.ImpersonatorEpoch,
		Ver:                sessionSchemaVer,
		CSRFToken:          csrf,
		CreatedAt:          now,
		ExpiresAt:          now.Add(m.ttl),
		ImpersonatorUserID: ns.ImpersonatorUserID,
		ImpersonatorEmail:  ns.ImpersonatorEmail,
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
	// Stale schema: drop it and force a fresh login rather than trust
	// zero-valued security fields.
	if s.Ver < sessionSchemaVer {
		m.rdb.Del(ctx, sessionKeyPrefix+c.Value)
		return nil, nil
	}
	// Durable revocation: a stale session dies here even when the Redis purge
	// that should have deleted it failed.
	if !m.epochValid(ctx, &s) {
		m.rdb.Del(ctx, sessionKeyPrefix+c.Value)
		return nil, nil
	}
	return &s, nil
}

// DestroyAllForUser scans every active session in Redis and deletes the ones
// belonging to `userID`, either as the effective identity or as the admin
// behind an impersonation. Returns the count of *confirmed* deletions and a
// non-nil error when any scan/read/delete failed, so callers never report a
// revocation that may not have happened. The durable guarantee is the auth
// epoch (see RevokeUser); this purge is the fast path.
//
// No cookie is cleared because the caller is not necessarily the same browser
// that owns the session being killed.
func (m *Manager) DestroyAllForUser(ctx context.Context, userID int64) (int, error) {
	if m == nil || m.rdb == nil {
		return 0, nil
	}
	var (
		cursor uint64
		killed int
		errs   []error
	)
	for {
		keys, next, err := m.rdb.Scan(ctx, cursor, sessionKeyPrefix+"*", 200).Result()
		if err != nil {
			errs = append(errs, fmt.Errorf("scan: %w", err))
			return killed, errors.Join(errs...)
		}
		for _, k := range keys {
			b, err := m.rdb.Get(ctx, k).Bytes()
			if isRedisMiss(err) {
				continue // expired between SCAN and GET: already gone
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("read %s: %w", k, err))
				continue
			}
			var s Session
			if uerr := json.Unmarshal(b, &s); uerr != nil {
				errs = append(errs, fmt.Errorf("decode %s: %w", k, uerr))
				continue
			}
			if s.UserID != userID && s.ImpersonatorUserID != userID {
				continue
			}
			n, derr := m.rdb.Del(ctx, k).Result()
			if derr != nil {
				errs = append(errs, fmt.Errorf("delete %s: %w", k, derr))
				continue
			}
			killed += int(n)
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return killed, errors.Join(errs...)
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

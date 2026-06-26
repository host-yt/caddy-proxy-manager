package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/redis/go-redis/v9"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/obs"
)

// PasskeyHandlers groups WebAuthn enrollment + login. WA is nil-safe: when
// it's nil all routes return 503 so the wider app keeps working before the
// admin configures App.URL correctly. Sessions / Mailer / DB plumbing comes
// from the surrounding handler bundle.
type PasskeyHandlers struct {
	DB       func() *sql.DB
	RDB      *redis.Client
	Sessions *auth.Manager
	Logger   *slog.Logger
	WA       *auth.WebAuthn
	Metrics  *obs.Metrics
}

// ---- enrollment ---------------------------------------------------------

// RegisterBegin returns the CredentialCreationOptions JSON the browser
// needs to call navigator.credentials.create(). Stores the matching session
// data in Redis under a random ticket; the finish endpoint reads it back.
//
// Auth: the caller must be a logged-in user (any role) - the route is
// mounted under both /admin/passkeys and /app/passkeys.
func (h *PasskeyHandlers) RegisterBegin(w http.ResponseWriter, r *http.Request) {
	if h.WA == nil {
		http.Error(w, "passkeys not configured", http.StatusServiceUnavailable)
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if sess == nil || db == nil {
		http.Error(w, "auth required", http.StatusUnauthorized)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	u, err := auth.LoadWAUser(ctx, db, sess.UserID)
	if err != nil {
		h.Logger.Error("passkey LoadWAUser failed", "err", err, "user_id", sess.UserID)
		http.Error(w, "load user failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Require user verification + prefer platform authenticators but accept
	// roaming (USB security keys). Resident key = "preferred" so passkeys
	// can be used for passwordless login later.
	opts, sessionData, err := h.WA.Lib().BeginRegistration(u,
		webauthn.WithExclusions(currentDescriptors(u)),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		}),
	)
	if err != nil {
		h.Logger.Error("webauthn BeginRegistration", "err", err, "user_id", sess.UserID)
		http.Error(w, "begin failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	ticket, err := h.stash(ctx, "wa:reg:", sessionData)
	if err != nil {
		http.Error(w, "stash failed", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "hpg_wa_reg", Value: ticket, Path: "/", HttpOnly: true,
		Secure: h.Sessions.CookieSecure(), SameSite: http.SameSiteLaxMode,
		Expires: time.Now().Add(auth.WebauthnTicketTTL),
	})
	writeJSON(w, http.StatusOK, opts)
}

// RegisterFinish persists the credential after the browser completes the
// ceremony. Expects raw JSON body produced by client-side
// `PublicKeyCredential.toJSON()` (passed through verbatim).
func (h *PasskeyHandlers) RegisterFinish(w http.ResponseWriter, r *http.Request) {
	if h.WA == nil {
		http.Error(w, "passkeys not configured", http.StatusServiceUnavailable)
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if sess == nil || db == nil {
		http.Error(w, "auth required", http.StatusUnauthorized)
		return
	}
	c, err := r.Cookie("hpg_wa_reg")
	if err != nil || c.Value == "" {
		http.Error(w, "no registration in progress", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	var sd webauthn.SessionData
	if err := h.consume(ctx, "wa:reg:"+c.Value, &sd); err != nil {
		http.Error(w, "registration expired", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "hpg_wa_reg", Value: "", Path: "/", MaxAge: -1})

	parsed, err := protocol.ParseCredentialCreationResponseBody(r.Body)
	if err != nil {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}
	u, err := auth.LoadWAUser(ctx, db, sess.UserID)
	if err != nil {
		http.Error(w, "load user failed", http.StatusInternalServerError)
		return
	}
	cred, err := h.WA.Lib().CreateCredential(u, sd, parsed)
	if err != nil {
		h.Logger.Warn("webauthn CreateCredential", "err", err)
		http.Error(w, "credential rejected: "+sanitizeErr(err), http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		name = "Passkey"
	}
	if _, err := auth.SaveCredential(ctx, db, sess.UserID, cred, name); err != nil {
		h.Metrics.PasskeyOp("register", "save_fail")
		http.Error(w, "save failed", http.StatusInternalServerError)
		return
	}
	h.Metrics.PasskeyOp("register", "success")
	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "passkey.register", Entity: "user",
		EntityID: fmt.Sprintf("%d", uid),
		Meta:     map[string]any{"name": name},
	})
	middleware.InvalidateAdmin2FACache(ctx, h.RDB, uid)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// List returns the user's enrolled passkeys (JSON; consumed by /account UI).
func (h *PasskeyHandlers) List(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if sess == nil || db == nil {
		http.Error(w, "auth required", http.StatusUnauthorized)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	rows, err := db.QueryContext(ctx,
		`SELECT id, name, transports, last_used_at, created_at
		   FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at DESC`,
		sess.UserID)
	if err != nil {
		// Most common cause: webauthn_credentials table missing (migration
		// 30 hasn't run). Logging the real cause beats "query failed" in
		// the browser console.
		h.Logger.Error("passkey list query failed", "err", err, "user_id", sess.UserID)
		http.Error(w, "passkey list failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type row struct {
		ID         int64      `json:"id"`
		Name       string     `json:"name"`
		Transports []string   `json:"transports"`
		LastUsed   *time.Time `json:"last_used_at,omitempty"`
		Created    time.Time  `json:"created_at"`
	}
	out := make([]row, 0, 4)
	for rows.Next() {
		var (
			id        int64
			name, ts  string
			lastUsed  sql.NullTime
			createdAt time.Time
		)
		if err := rows.Scan(&id, &name, &ts, &lastUsed, &createdAt); err != nil {
			continue
		}
		var tlist []string
		for _, t := range strings.Split(ts, ",") {
			if t = strings.TrimSpace(t); t != "" {
				tlist = append(tlist, t)
			}
		}
		r := row{ID: id, Name: name, Transports: tlist, Created: createdAt}
		if lastUsed.Valid {
			r.LastUsed = &lastUsed.Time
		}
		out = append(out, r)
	}
	writeJSON(w, http.StatusOK, out)
}

// Delete removes one of the user's own passkeys.
func (h *PasskeyHandlers) Delete(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if sess == nil || db == nil {
		http.Error(w, "auth required", http.StatusUnauthorized)
		return
	}
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := auth.DeleteCredential(ctx, db, sess.UserID, id); err != nil {
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "passkey.delete", Entity: "user",
		EntityID: fmt.Sprintf("%d", uid),
		Meta:     map[string]any{"credential_pk": id},
	})
	middleware.InvalidateAdmin2FACache(ctx, h.RDB, uid)
	w.WriteHeader(http.StatusNoContent)
}

// ---- login (discoverable, passwordless) --------------------------------

// LoginBegin produces an assertion request for discoverable-credential
// login (passwordless). Browser picks the credential; we resolve the user
// from credential_id at the finish step.
func (h *PasskeyHandlers) LoginBegin(w http.ResponseWriter, r *http.Request) {
	if h.WA == nil {
		http.Error(w, "passkeys not configured", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	opts, sessionData, err := h.WA.Lib().BeginDiscoverableLogin()
	if err != nil {
		h.Logger.Error("webauthn BeginDiscoverableLogin", "err", err)
		http.Error(w, "begin failed", http.StatusInternalServerError)
		return
	}
	ticket, err := h.stash(ctx, "wa:login:", sessionData)
	if err != nil {
		http.Error(w, "stash failed", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "hpg_wa_login", Value: ticket, Path: "/", HttpOnly: true,
		Secure: h.Sessions.CookieSecure(), SameSite: http.SameSiteLaxMode,
		Expires: time.Now().Add(auth.WebauthnTicketTTL),
	})
	writeJSON(w, http.StatusOK, opts)
}

// LoginFinish verifies the assertion + creates a panel session. Returns a
// JSON {"redirect":"/admin"} or {"redirect":"/app"} so the JS knows where
// to navigate after success.
func (h *PasskeyHandlers) LoginFinish(w http.ResponseWriter, r *http.Request) {
	if h.WA == nil {
		http.Error(w, "passkeys not configured", http.StatusServiceUnavailable)
		return
	}
	db := h.DB()
	if db == nil {
		http.Error(w, "db unavailable", http.StatusServiceUnavailable)
		return
	}
	c, err := r.Cookie("hpg_wa_login")
	if err != nil || c.Value == "" {
		http.Error(w, "no login in progress", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	var sd webauthn.SessionData
	if err := h.consume(ctx, "wa:login:"+c.Value, &sd); err != nil {
		http.Error(w, "login expired", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "hpg_wa_login", Value: "", Path: "/", MaxAge: -1})

	parsed, err := protocol.ParseCredentialRequestResponseBody(r.Body)
	if err != nil {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}

	var resolvedUser *auth.WAUser
	cred, err := h.WA.Lib().ValidateDiscoverableLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
		u, err := auth.FindUserByCredentialID(ctx, db, rawID)
		if err != nil {
			return nil, err
		}
		resolvedUser = u
		return u, nil
	}, sd, parsed)
	if err != nil || resolvedUser == nil {
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			Action: "login.fail", Entity: "auth",
			Meta: map[string]any{"reason": "passkey_invalid", "err": fmt.Sprintf("%v", err)},
		})
		h.Metrics.PasskeyOp("login", "fail")
		h.Metrics.LoginEvent("fail", "passkey", "passkey")
		http.Error(w, "assertion rejected", http.StatusUnauthorized)
		return
	}
	if err := auth.BumpSignCount(ctx, db, cred.ID, cred.Authenticator.SignCount); err != nil {
		h.Logger.Warn("webauthn sign count update", "err", err)
	}

	// Resolve role + client scope + active state, mirroring password login.
	var (
		role     string
		clientID int64
		isActive bool
	)
	_ = db.QueryRowContext(ctx,
		`SELECT role, is_active FROM users WHERE id = ?`, resolvedUser.ID,
	).Scan(&role, &isActive)
	if !isActive {
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			UserID: &resolvedUser.ID, Action: "login.fail", Entity: "auth", EntityID: resolvedUser.Email,
			Meta: map[string]any{"reason": "disabled", "via": "passkey"},
		})
		http.Error(w, "account disabled", http.StatusForbidden)
		return
	}
	if role == "client" {
		_ = db.QueryRowContext(ctx, `SELECT id FROM clients WHERE user_id = ?`, resolvedUser.ID).Scan(&clientID)
	}
	if _, err := h.Sessions.Create(ctx, w, resolvedUser.ID, resolvedUser.Email, role, clientID); err != nil {
		h.Logger.Error("session create", "err", err)
		http.Error(w, "session create failed", http.StatusInternalServerError)
		return
	}
	_, _ = db.ExecContext(ctx, `UPDATE users SET last_login_at = NOW() WHERE id = ?`, resolvedUser.ID)
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &resolvedUser.ID, Action: "login.success", Entity: "auth", EntityID: resolvedUser.Email,
		Meta: map[string]any{"role": role, "via": "passkey", "mfa": "passkey"},
	})
	h.Metrics.PasskeyOp("login", "success")
	h.Metrics.LoginEvent("success", "passkey", "passkey")
	h.Metrics.SessionEvent("create")
	dest := "/admin"
	if role == "client" {
		dest = "/app"
	}
	writeJSON(w, http.StatusOK, map[string]any{"redirect": dest})
}

// ---- helpers ------------------------------------------------------------

func (h *PasskeyHandlers) stash(ctx context.Context, prefix string, sd *webauthn.SessionData) (string, error) {
	ticket, err := auth.NewSessionTicket()
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(sd)
	if err != nil {
		return "", err
	}
	if err := h.RDB.Set(ctx, prefix+ticket, b, auth.WebauthnTicketTTL).Err(); err != nil {
		return "", err
	}
	return ticket, nil
}

func (h *PasskeyHandlers) consume(ctx context.Context, key string, out *webauthn.SessionData) error {
	b, err := h.RDB.Get(ctx, key).Bytes()
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, out); err != nil {
		return err
	}
	_ = h.RDB.Del(ctx, key).Err()
	return nil
}

func currentDescriptors(u *auth.WAUser) []protocol.CredentialDescriptor {
	out := make([]protocol.CredentialDescriptor, 0, len(u.Creds))
	for _, c := range u.Creds {
		out = append(out, c.Descriptor())
	}
	return out
}

// errPasskeyUnauthorized is returned by Validate*Login when the credential
// is unknown - kept as an explicit constant in case future audit logic
// needs to distinguish "unknown credential" from "bad signature".
var errPasskeyUnauthorized = errors.New("passkey: unauthorized")

var _ = errPasskeyUnauthorized

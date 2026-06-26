package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// OAuthIdentityHandlers manages the link/unlink UI for oauth_identities.
// Shared between /admin/oauth-identities and /app/oauth-identities routes.
type OAuthIdentityHandlers struct {
	DB     func() *sql.DB
	Logger *slog.Logger
}

type oauthIdentityRow struct {
	ID       int64
	Provider string
	Label    string // display-friendly provider name
	Email    string
	LinkedAt time.Time
}

// listIdentities returns the OAuth identities linked to userID.
func listIdentities(ctx context.Context, db *sql.DB, userID int64) ([]oauthIdentityRow, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, provider, COALESCE(email,''), linked_at
		   FROM oauth_identities WHERE user_id = ? ORDER BY linked_at ASC`,
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []oauthIdentityRow
	for rows.Next() {
		var row oauthIdentityRow
		if err := rows.Scan(&row.ID, &row.Provider, &row.Email, &row.LinkedAt); err != nil {
			continue
		}
		row.Label = FormatProviderLabel(row.Provider)
		out = append(out, row)
	}
	return out, rows.Err()
}

// rowQuerier is satisfied by both *sql.DB and *sql.Tx so loginMethodCount can
// run inside the unlink transaction (where it must see the locked snapshot).
type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// loginMethodCount returns the total number of independent login paths for the
// user. Each oauth identity counts separately so a user with 2 OAuth providers
// can unlink one while keeping the other. Fails closed: any query error is
// returned so callers never delete a credential on a partial/incorrect count.
func loginMethodCount(ctx context.Context, q rowQuerier, userID int64) (int, error) {
	var methods int

	// Real usable password (set via reset or change, not a dummy OIDC hash).
	var pwdSet int
	if err := q.QueryRowContext(ctx,
		`SELECT COALESCE(password_set, 0) FROM users WHERE id = ?`, userID,
	).Scan(&pwdSet); err != nil {
		return 0, err
	}
	if pwdSet == 1 {
		methods++
	}

	// Each passkey is an independent login path.
	var passkeys int
	if err := q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?`, userID,
	).Scan(&passkeys); err != nil {
		return 0, err
	}
	methods += passkeys

	// Each linked OAuth identity is an independent login path.
	var oauthCount int
	if err := q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM oauth_identities WHERE user_id = ?`, userID,
	).Scan(&oauthCount); err != nil {
		return 0, err
	}
	methods += oauthCount

	return methods, nil
}

// List returns a JSON array of the caller's linked OAuth providers.
func (h *OAuthIdentityHandlers) List(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if sess == nil || db == nil {
		http.Error(w, "auth required", http.StatusUnauthorized)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	rows, err := listIdentities(ctx, db, sess.UserID)
	if err != nil {
		h.Logger.Error("oauth identities list", "err", err, "user_id", sess.UserID)
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	type out struct {
		ID       int64  `json:"id"`
		Provider string `json:"provider"`
		Email    string `json:"email"`
		LinkedAt string `json:"linked_at"`
	}
	result := make([]out, 0, len(rows))
	for _, row := range rows {
		result = append(result, out{
			ID:       row.ID,
			Provider: row.Provider,
			Email:    row.Email,
			LinkedAt: row.LinkedAt.UTC().Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, result)
}

// Unlink removes one linked OAuth provider from the authenticated user.
// Returns 409 when it would remove the last login method.
func (h *OAuthIdentityHandlers) Unlink(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if sess == nil || db == nil {
		http.Error(w, "auth required", http.StatusUnauthorized)
		return
	}
	// Target the exact identity row by its immutable id, not by provider: a user
	// can hold several rows for one provider (different issuers / config changes),
	// so a provider+LIMIT 1 delete could remove the wrong credential.
	identityID, idErr := strconv.ParseInt(strings.TrimSpace(chi.URLParam(r, "id")), 10, 64)
	if idErr != nil || identityID <= 0 {
		http.Error(w, "identity id required", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Serialize login-method removal per user: lock the user row, then count and
	// delete inside one transaction. Two concurrent unlinks would otherwise both
	// read methods==2, both pass the guard, and both delete -> last-method
	// lockout. FOR UPDATE makes the second unlink wait for the first to commit
	// and re-read the now-reduced count.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		http.Error(w, "unlink failed", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback() // no-op after a successful Commit

	var lockUID int64
	if err := tx.QueryRowContext(ctx,
		`SELECT id FROM users WHERE id = ? FOR UPDATE`, sess.UserID,
	).Scan(&lockUID); err != nil {
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}

	// Verify the identity exists and belongs to this user (ownership by user_id).
	var provider string
	var identityEmail string
	err = tx.QueryRowContext(ctx,
		`SELECT provider, COALESCE(email,'') FROM oauth_identities WHERE id = ? AND user_id = ? LIMIT 1`,
		identityID, sess.UserID,
	).Scan(&provider, &identityEmail)
	if err == sql.ErrNoRows {
		http.Error(w, "identity not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}

	// Refuse unlink when removing this identity would leave no login method.
	// Count inside the tx (locked snapshot); fail closed on a count error so we
	// never delete on an undercount. methods counts each OAuth identity
	// separately, so (methods-1) >= 1 means at least one path remains.
	methods, cerr := loginMethodCount(ctx, tx, sess.UserID)
	if cerr != nil {
		h.Logger.Error("oauth unlink count", "err", cerr, "user_id", sess.UserID)
		http.Error(w, "unlink failed", http.StatusInternalServerError)
		return
	}
	if methods-1 < 1 {
		uid := sess.UserID
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			UserID: &uid, Action: "oauth.unlink.denied", Entity: "user",
			EntityID: itoa64(uid),
			Meta:     map[string]any{"provider": provider, "reason": "last_login_method"},
		})
		http.Error(w, "cannot remove last login method", http.StatusConflict)
		return
	}

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM oauth_identities WHERE id = ? AND user_id = ?`,
		identityID, sess.UserID,
	); err != nil {
		http.Error(w, "unlink failed", http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(); err != nil {
		http.Error(w, "unlink failed", http.StatusInternalServerError)
		return
	}

	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "oauth.unlink", Entity: "user",
		EntityID: itoa64(uid),
		Meta: map[string]any{
			"provider": provider,
			"email":    identityEmail,
		},
	})
	w.WriteHeader(http.StatusNoContent)
}

// LinkOIDC links the currently configured OIDC provider to the authenticated
// user's account. The user must already be logged in; this redirects through
// /auth/oidc/start which stores a "link_user_id" hint in the state payload.
// The OIDCCallback handler reads that hint and calls CompleteLink instead of
// the normal find-or-provision flow.
func (h *OAuthIdentityHandlers) LinkOIDC(w http.ResponseWriter, r *http.Request) {
	// Redirect to /auth/oidc/start with ?link=1 query param so OIDCStart
	// knows to embed the session user-id into the state payload.
	http.Redirect(w, r, "/auth/oidc/start?link=1", http.StatusSeeOther)
}

// SaveIdentity upserts an OAuth identity row. Called from OIDCCallback on
// login and from the explicit link flow. Issuer is part of the unique key
// because subjects are only unique within an issuer.
//
// Ownership is IMMUTABLE: a duplicate (provider,issuer,subject) only refreshes
// the email, never reassigns user_id. Without this a duplicate insert from a
// second user could silently steal an already-linked identity (the precheck in
// the link flow is a separate statement, so a concurrent insert can race it).
// A duplicate owned by another user is reported via ErrIdentityOwnedByOther so
// callers can fail closed. The email refresh is itself gated on ownership: the
// IF() only updates email when the existing row's user_id matches this caller,
// so a foreign link attempt cannot mutate the real owner's stored email before
// the ownership check below rejects it (cross-account data corruption).
func SaveIdentity(ctx context.Context, db *sql.DB, userID int64, provider, subject, email, issuer string) error {
	res, err := db.ExecContext(ctx,
		`INSERT INTO oauth_identities (user_id, provider, subject, email, issuer)
		 VALUES (?, ?, ?, NULLIF(?, ''), ?)
		 ON DUPLICATE KEY UPDATE
		   email = IF(user_id = VALUES(user_id), COALESCE(VALUES(email), email), email)`,
		userID, provider, subject, email, issuer,
	)
	if err != nil {
		return err
	}
	// MySQL returns rowsAffected: 1 for a fresh insert, 2 when an existing row
	// was updated, 0 when it matched but nothing changed. On any duplicate (0/2)
	// confirm the row belongs to this user; if not, the identity is owned by
	// someone else and we must not pretend the link/login succeeded.
	if n, _ := res.RowsAffected(); n != 1 {
		var owner int64
		qerr := db.QueryRowContext(ctx,
			`SELECT user_id FROM oauth_identities WHERE provider = ? AND issuer = ? AND subject = ? LIMIT 1`,
			provider, issuer, subject,
		).Scan(&owner)
		if qerr != nil {
			return qerr
		}
		if owner != userID {
			return ErrIdentityOwnedByOther
		}
	}
	return nil
}

// ErrIdentityOwnedByOther signals a duplicate (provider,issuer,subject) already
// linked to a different user - the caller must treat this as a hard failure.
var ErrIdentityOwnedByOther = fmt.Errorf("oauth identity already linked to another user")

// FormatProviderLabel returns a display-friendly name for a provider slug.
func FormatProviderLabel(p string) string {
	switch strings.ToLower(p) {
	case "github":
		return "GitHub"
	case "google":
		return "Google"
	case "microsoft":
		return "Microsoft"
	case "gitlab":
		return "GitLab"
	case "authentik":
		return "Authentik"
	default:
		if p == "" {
			return "Unknown"
		}
		return fmt.Sprintf("%s%s", strings.ToUpper(p[:1]), p[1:])
	}
}

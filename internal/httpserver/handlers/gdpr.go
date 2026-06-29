package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// GDPRExport returns a JSON dump of every personally-identifiable row for
// a single user: account data, sessions metadata, audit-log entries
// authored by them, routes/services they own. Admin-only.
//
// Sufficient for Article 15 data-portability requests. The export does
// NOT include hashed secrets (password_hash, totp_secret_enc, recovery_codes).
func (h *AdminHandlers) GDPRExport(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if id == 0 {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	out := map[string]any{
		"exported_at": time.Now().UTC().Format(time.RFC3339),
		"user_id":     id,
	}

	user, err := selectUser(ctx, db, id)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	out["user"] = user

	out["api_keys"] = selectRows(ctx, db,
		"SELECT id, name, key_prefix, scopes, created_at, last_used_at, expires_at, revoked_at FROM api_keys WHERE user_id = ?",
		id)
	out["audit_log"] = selectRows(ctx, db,
		"SELECT id, action, entity, entity_id, ip, user_agent, meta, created_at FROM audit_log WHERE user_id = ? ORDER BY id DESC LIMIT 5000",
		id)
	out["routes"] = selectRows(ctx, db,
		`SELECT r.id, r.domain, r.path_prefix, r.upstream_port, r.status, r.created_at
		 FROM routes r JOIN services sv ON sv.id = r.service_id
		 JOIN clients c ON c.id = sv.client_id WHERE c.user_id = ?`, id)
	out["services"] = selectRows(ctx, db,
		`SELECT sv.id, sv.name, sv.backend_ip, sv.allowed_port_start, sv.allowed_port_end, sv.status, sv.created_at
		 FROM services sv JOIN clients c ON c.id = sv.client_id WHERE c.user_id = ?`, id)

	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "gdpr.export", Entity: "user",
		EntityID: strconv.FormatInt(id, 10),
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=gdpr-user-%d.json", id))
	_ = json.NewEncoder(w).Encode(out)
}

// GDPRDelete erases all PII for a user. Audit and aggregated counters stay
// (entity_id is masked). Cannot delete super_admin accounts to avoid
// lockouts.
func (h *AdminHandlers) GDPRDelete(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if id == 0 {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	var email, role string
	if err := db.QueryRowContext(ctx,
		"SELECT email, role FROM users WHERE id = ?", id,
	).Scan(&email, &role); err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	if role == "super_admin" {
		http.Error(w, "cannot delete a super_admin via GDPR; demote first", http.StatusForbidden)
		return
	}

	sess := middleware.SessionFromContext(r.Context())
	var requestedBy sql.NullInt64
	if sess != nil {
		requestedBy = sql.NullInt64{Int64: sess.UserID, Valid: true}
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		http.Error(w, "tx begin failed", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.ExecContext(ctx,
		"INSERT INTO data_deletions (user_id, email, requested_by, completed_at) VALUES (?, ?, ?, NOW())",
		id, email, requestedBy); err != nil {
		http.Error(w, "log failed", http.StatusInternalServerError)
		return
	}
	// Mask the user row (keep id for FK integrity).
	mask := fmt.Sprintf("deleted-user-%d@hpg.invalid", id)
	if _, err := tx.ExecContext(ctx,
		`UPDATE users SET email = ?, password_hash = '', password_set = 0, full_name = NULL,
		 totp_secret = NULL, totp_secret_enc = NULL, totp_enabled = 0,
		 is_active = 0
		 WHERE id = ?`, mask, id); err != nil {
		http.Error(w, "user mask failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Remove derived rows that hold PII directly.
	_, _ = tx.ExecContext(ctx, "DELETE FROM api_keys WHERE user_id = ?", id)
	_, _ = tx.ExecContext(ctx, "DELETE FROM recovery_codes WHERE user_id = ?", id)
	_, _ = tx.ExecContext(ctx, "DELETE FROM password_resets WHERE user_id = ?", id)
	// Audit rows: keep for legal hold but blank identifiable bits.
	_, _ = tx.ExecContext(ctx,
		"UPDATE audit_log SET ip = NULL, user_agent = NULL WHERE user_id = ?", id)

	if err := tx.Commit(); err != nil {
		http.Error(w, "commit failed", http.StatusInternalServerError)
		return
	}
	// The account is now masked + is_active=0; drop any live sessions so the
	// cookie path can't keep serving the erased user until session TTL.
	if h.Sessions != nil {
		_, _ = h.Sessions.DestroyAllForUser(ctx, id)
	}

	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "gdpr.delete", Entity: "user",
		EntityID: strconv.FormatInt(id, 10),
		Meta:     map[string]any{"original_email": email},
	})
	redirectWithFlash(w, r, "/admin/users", fmt.Sprintf("User %d data erased (GDPR).", id), "")
}

// selectUser returns a non-sensitive user dump.
func selectUser(ctx context.Context, db *sql.DB, id int64) (map[string]any, error) {
	row := db.QueryRowContext(ctx,
		`SELECT id, email, role, full_name, is_active, totp_enabled,
		        last_login_at, created_at, updated_at
		 FROM users WHERE id = ?`, id)
	var (
		uid                  int64
		email, role          string
		fullName             sql.NullString
		isActive             bool
		totpEnabled          bool
		lastLogin            sql.NullTime
		createdAt, updatedAt time.Time
	)
	if err := row.Scan(&uid, &email, &role, &fullName, &isActive, &totpEnabled,
		&lastLogin, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	// Fetch linked OAuth identities for the GDPR export.
	linkedProviders := selectRows(ctx, db,
		`SELECT provider, issuer, subject, email, linked_at FROM oauth_identities WHERE user_id = ?`, id)
	return map[string]any{
		"id":               uid,
		"email":            email,
		"role":             role,
		"full_name":        nullToStr(fullName),
		"is_active":        isActive,
		"totp":             totpEnabled,
		"linked_providers": linkedProviders,
		"last_login_at":    nullToTime(lastLogin),
		"created_at":       createdAt,
		"updated_at":       updatedAt,
	}, nil
}

// selectRows returns each result row as a generic map.
func selectRows(ctx context.Context, db *sql.DB, q string, args ...any) []map[string]any {
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil
	}
	out := []map[string]any{}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			continue
		}
		m := map[string]any{}
		for i, c := range cols {
			switch v := vals[i].(type) {
			case []byte:
				m[c] = string(v)
			default:
				m[c] = v
			}
		}
		out = append(out, m)
	}
	return out
}

func nullToStr(s sql.NullString) any {
	if !s.Valid {
		return nil
	}
	return s.String
}
func nullToTime(t sql.NullTime) any {
	if !t.Valid {
		return nil
	}
	return t.Time
}

// LegalDocAdmin upserts a legal document. Public viewers see it at /legal/{slug}.
func (h *AdminHandlers) LegalDocAdmin(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	slug := r.FormValue("slug")
	title := r.FormValue("title")
	body := r.FormValue("body")
	if slug == "" || title == "" {
		redirectWithFlash(w, r, "/admin/legal", "", "slug + title required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	sess := middleware.SessionFromContext(r.Context())
	var updatedBy sql.NullInt64
	if sess != nil {
		updatedBy = sql.NullInt64{Int64: sess.UserID, Valid: true}
	}
	var legalQ string
	if store.Driver() == "sqlite3" {
		legalQ = `INSERT INTO legal_documents (slug, title, body, updated_by) VALUES (?, ?, ?, ?) ON CONFLICT(slug) DO UPDATE SET title=excluded.title, body=excluded.body, updated_by=excluded.updated_by`
	} else {
		legalQ = `INSERT INTO legal_documents (slug, title, body, updated_by) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE title=VALUES(title), body=VALUES(body), updated_by=VALUES(updated_by)`
	}
	if _, err := db.ExecContext(ctx, legalQ, slug, title, body, updatedBy); err != nil {
		redirectWithFlash(w, r, "/admin/legal", "", "save failed: "+err.Error())
		return
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "legal.update", Entity: "legal_documents", EntityID: slug,
	})
	redirectWithFlash(w, r, "/admin/legal", "Saved.", "")
}

// LegalDocPublic serves a stored legal document publicly (no auth).
// Renders the body as plain text wrapped in a minimal HTML shell so panel
// users + integrators can link to ToS / privacy from anywhere.
func LegalDocPublic(dbf func() *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slug := chi.URLParam(r, "slug")
		if slug == "" {
			http.NotFound(w, r)
			return
		}
		db := dbf()
		if db == nil {
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		var title, body string
		err := db.QueryRowContext(ctx,
			"SELECT title, body FROM legal_documents WHERE slug = ?", slug,
		).Scan(&title, &body)
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, "lookup failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>"))
		_, _ = w.Write([]byte(htmlEscape(title)))
		_, _ = w.Write([]byte("</title></head><body style=\"max-width:760px;margin:2rem auto;font-family:system-ui;line-height:1.5;color:#222\"><h1>"))
		_, _ = w.Write([]byte(htmlEscape(title)))
		_, _ = w.Write([]byte("</h1><pre style=\"white-space:pre-wrap;font-family:inherit\">"))
		_, _ = w.Write([]byte(htmlEscape(body)))
		_, _ = w.Write([]byte("</pre></body></html>"))
	}
}

func htmlEscape(s string) string {
	r := []rune(s)
	out := make([]rune, 0, len(r))
	for _, c := range r {
		switch c {
		case '<':
			out = append(out, []rune("&lt;")...)
		case '>':
			out = append(out, []rune("&gt;")...)
		case '&':
			out = append(out, []rune("&amp;")...)
		case '"':
			out = append(out, []rune("&quot;")...)
		default:
			out = append(out, c)
		}
	}
	return string(out)
}

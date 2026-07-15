package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/mtls"
)

// mtlsCARow is the display shape for one CA (no key material).
type mtlsCARow struct {
	ID         int64
	Name       string
	CommonName string
	ClientID   sql.NullInt64
	NotAfter   string
	Status     string
	Expired    bool
	Certs      []mtlsCertRow
	// Roles lists RBAC roles defined for this CA.
	Roles []mtlsRoleRow
}

// mtlsCertRow is the display shape for one issued client cert (no key material).
type mtlsCertRow struct {
	ID        int64
	Subject   string
	Serial    string
	NotAfter  string
	Status    string
	Revoked   bool
	Expired   bool
	IssuedAt  string
	RevokedAt string
	// AssignedRoles lists roles currently assigned to this cert.
	AssignedRoles []mtlsRoleRow
}

// mtlsBundle holds freshly issued material shown exactly once after Issue.
// The private key is never persisted and only lives in this single response.
type mtlsBundle struct {
	Subject string
	Serial  string
	CertPEM string
	KeyPEM  string
}

type mtlsData struct {
	baseAdminData
	CAs    []mtlsCARow
	Total  int
	Bundle *mtlsBundle // non-nil immediately after a successful issue
}

// mtlsScopeDenied reports whether the caller may NOT manage mTLS authorities.
// CAs are operator-global trust anchors (no per-client scope), so a scoped
// admin (non-super_admin with AdminScope wired) is blocked outright. It writes
// the 403 response when access is denied. Mirrors the WAF global-suppression
// guard pattern other privileged admin handlers use.
func (h *AdminHandlers) mtlsScopeDenied(w http.ResponseWriter, r *http.Request) bool {
	sess := middleware.SessionFromContext(r.Context())
	if sess == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return true
	}
	if sess.Role != "super_admin" && h.AdminScope != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return true
	}
	return false
}

// mtlsSvc returns a ready-to-use Service or nil when deps are missing.
func (h *AdminHandlers) mtlsSvc() *mtls.Service {
	if h.DB == nil || h.State == nil {
		return nil
	}
	return &mtls.Service{
		DB:      h.DB,
		Encrypt: h.State.Encrypt,
		Decrypt: h.State.Decrypt,
	}
}

// loadMTLSView builds the full CA + issued-cert tree for the list page,
// including roles per CA and assigned roles per cert.
func (h *AdminHandlers) loadMTLSView(ctx context.Context, svc *mtls.Service) ([]mtlsCARow, error) {
	cas, err := svc.ListCAs(ctx)
	if err != nil {
		return nil, err
	}
	db := h.DB()
	out := make([]mtlsCARow, 0, len(cas))
	for _, ca := range cas {
		row := mtlsCARow{
			ID:         ca.ID,
			Name:       ca.Name,
			CommonName: ca.CommonName,
			ClientID:   ca.ClientID,
			NotAfter:   ca.NotAfter.UTC().Format("2006-01-02"),
			Status:     ca.Status,
			Expired:    time.Now().After(ca.NotAfter),
		}
		// Load roles for this CA.
		if db != nil {
			if rr, rerr := db.QueryContext(ctx,
				`SELECT id, name FROM mtls_roles WHERE ca_id=? ORDER BY name ASC`, ca.ID); rerr == nil {
				for rr.Next() {
					var ro mtlsRoleRow
					if rr.Scan(&ro.ID, &ro.Name) == nil {
						row.Roles = append(row.Roles, ro)
					}
				}
				rr.Close()
			}
		}

		issued, ierr := svc.ListIssued(ctx, ca.ID)
		if ierr != nil {
			return nil, ierr
		}
		for _, c := range issued {
			cr := mtlsCertRow{
				ID:       c.ID,
				Subject:  c.Subject,
				Serial:   c.Serial,
				NotAfter: c.NotAfter.UTC().Format("2006-01-02"),
				Status:   c.Status,
				Revoked:  c.Revoked(),
				Expired:  c.Expired(),
				IssuedAt: c.IssuedAt.UTC().Format("2006-01-02"),
			}
			if c.RevokedAt.Valid {
				cr.RevokedAt = c.RevokedAt.Time.UTC().Format("2006-01-02")
			}
			// Load roles assigned to this cert.
			if db != nil {
				if ar, arerr := db.QueryContext(ctx, `
					SELECT ro.id, ro.name
					  FROM mtls_cert_roles cr
					  JOIN mtls_roles ro ON ro.id = cr.role_id
					 WHERE cr.cert_id = ?
					 ORDER BY ro.name ASC`, c.ID); arerr == nil {
					for ar.Next() {
						var ro mtlsRoleRow
						if ar.Scan(&ro.ID, &ro.Name) == nil {
							cr.AssignedRoles = append(cr.AssignedRoles, ro)
						}
					}
					ar.Close()
				}
			}
			row.Certs = append(row.Certs, cr)
		}
		out = append(out, row)
	}
	return out, nil
}

// MTLSList GET /admin/mtls - list CAs and their issued client certs.
func (h *AdminHandlers) MTLSList(w http.ResponseWriter, r *http.Request) {
	if h.mtlsScopeDenied(w, r) {
		return
	}
	d := mtlsData{baseAdminData: h.base(r, "mTLS Authorities")}
	svc := h.mtlsSvc()
	if svc == nil {
		d.Error = "crypto not configured"
		h.render(w, "mtls", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	rows, err := h.loadMTLSView(ctx, svc)
	if err != nil {
		h.Logger.Error("mtls list", "err", err)
		d.Error = "Could not load mTLS CAs. Refresh to retry; if it persists, check the panel logs for 'mtls list'."
		h.render(w, "mtls", d)
		return
	}
	d.CAs = rows
	d.Total = len(rows)
	h.render(w, "mtls", d)
}

// MTLSCreateCA POST /admin/mtls/ca - generate a new per-tenant/operator CA.
func (h *AdminHandlers) MTLSCreateCA(w http.ResponseWriter, r *http.Request) {
	if h.mtlsScopeDenied(w, r) {
		return
	}
	const page = "/admin/mtls"
	svc := h.mtlsSvc()
	if svc == nil {
		redirectWithFlash(w, r, page, "", "crypto not configured")
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectWithFlash(w, r, page, "", "form parse error")
		return
	}
	in := mtls.CreateCAInput{
		Name:       r.FormValue("name"),
		CommonName: r.FormValue("common_name"),
	}
	if v := r.FormValue("client_id"); v != "" {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil && id > 0 {
			in.ClientID = sql.NullInt64{Int64: id, Valid: true}
		}
	}
	if v := r.FormValue("valid_days"); v != "" {
		if days, err := strconv.Atoi(v); err == nil && days > 0 {
			in.ValidFor = time.Duration(days) * 24 * time.Hour
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	id, err := svc.CreateCA(ctx, in)
	if err != nil {
		redirectWithFlash(w, r, page, "", "create CA failed: "+sanitizeErr(err))
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "mtls.ca.create", Entity: "mtls_ca",
		EntityID: strconv.FormatInt(id, 10),
		Meta:     map[string]any{"name": in.Name}, // never log key material
	})
	redirectWithFlash(w, r, page, "Certificate authority created.", "")
}

// MTLSDeleteCA POST /admin/mtls/ca/{id}/delete - remove a CA and its issued certs.
func (h *AdminHandlers) MTLSDeleteCA(w http.ResponseWriter, r *http.Request) {
	if h.mtlsScopeDenied(w, r) {
		return
	}
	const page = "/admin/mtls"
	svc := h.mtlsSvc()
	if svc == nil {
		redirectWithFlash(w, r, page, "", "service unavailable")
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		redirectWithFlash(w, r, page, "", "invalid id")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := svc.DeleteCA(ctx, id); err != nil {
		redirectWithFlash(w, r, page, "", "delete failed: "+sanitizeErr(err))
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "mtls.ca.delete", Entity: "mtls_ca",
		EntityID: strconv.FormatInt(id, 10),
	})
	redirectWithFlash(w, r, page, "Certificate authority deleted.", "")
}

// MTLSIssue POST /admin/mtls/ca/{id}/issue - mint a client cert. The private key
// is shown exactly once on the rendered page and never stored.
func (h *AdminHandlers) MTLSIssue(w http.ResponseWriter, r *http.Request) {
	if h.mtlsScopeDenied(w, r) {
		return
	}
	const page = "/admin/mtls"
	svc := h.mtlsSvc()
	if svc == nil {
		redirectWithFlash(w, r, page, "", "crypto not configured")
		return
	}
	caID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || caID <= 0 {
		redirectWithFlash(w, r, page, "", "invalid CA id")
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectWithFlash(w, r, page, "", "form parse error")
		return
	}
	in := mtls.IssueInput{CAID: caID, Subject: r.FormValue("subject")}
	if v := r.FormValue("valid_days"); v != "" {
		if days, err := strconv.Atoi(v); err == nil && days > 0 {
			in.ValidFor = time.Duration(days) * 24 * time.Hour
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	res, err := svc.Issue(ctx, in)
	if err != nil {
		redirectWithFlash(w, r, page, "", "issue failed: "+sanitizeErr(err))
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "mtls.cert.issue", Entity: "mtls_cert",
		EntityID: strconv.FormatInt(res.ID, 10),
		Meta:     map[string]any{"ca_id": caID, "subject": in.Subject, "serial": res.Serial}, // never log the key
	})

	// Render the page directly with the one-shot bundle (cert + private key).
	// Redirecting would drop the key, which is never persisted server-side.
	d := mtlsData{baseAdminData: h.base(r, "mTLS Authorities")}
	d.Flash = "Client certificate issued. Copy the private key now - it is shown only once."
	if rows, lerr := h.loadMTLSView(ctx, svc); lerr == nil {
		d.CAs = rows
		d.Total = len(rows)
	}
	d.Bundle = &mtlsBundle{
		Subject: in.Subject,
		Serial:  res.Serial,
		CertPEM: res.CertPEM,
		KeyPEM:  res.KeyPEM,
	}
	w.Header().Set("Cache-Control", "no-store") // do not cache the one-time key
	h.render(w, "mtls", d)
}

// MTLSRevoke POST /admin/mtls/cert/{id}/revoke - revoke an issued client cert.
func (h *AdminHandlers) MTLSRevoke(w http.ResponseWriter, r *http.Request) {
	if h.mtlsScopeDenied(w, r) {
		return
	}
	const page = "/admin/mtls"
	svc := h.mtlsSvc()
	if svc == nil {
		redirectWithFlash(w, r, page, "", "service unavailable")
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		redirectWithFlash(w, r, page, "", "invalid id")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := svc.Revoke(ctx, id); err != nil {
		redirectWithFlash(w, r, page, "", "revoke failed: "+sanitizeErr(err))
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "mtls.cert.revoke", Entity: "mtls_cert",
		EntityID: strconv.FormatInt(id, 10),
	})
	redirectWithFlash(w, r, page, "Client certificate revoked.", "")
}

// MTLSCABundle GET /admin/mtls/ca/{id}/bundle.pem - download a CA's public cert
// PEM. This is the trust material clients import / admins distribute so issued
// client certs can be verified. No private key is ever exposed.
func (h *AdminHandlers) MTLSCABundle(w http.ResponseWriter, r *http.Request) {
	if h.mtlsScopeDenied(w, r) {
		return
	}
	svc := h.mtlsSvc()
	if svc == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	ca, err := svc.GetCA(ctx, id)
	if err != nil {
		http.Error(w, "CA not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"ca-%d.pem\"", id))
	_, _ = io.WriteString(w, ca.CertPEM)
}

// mtlsCRLData is the revocation-list view: revoked + still-valid certs for a CA.
type mtlsCRLData struct {
	baseAdminData
	CAID    int64
	CAName  string
	Revoked []mtlsCertRow // revoked rows only (CRL-style status list)
}

// MTLSCRL GET /admin/mtls/ca/{id}/crl - revocation view derived from the
// issued-certs table (revoked rows). Reuses ListIssued; no new store method.
func (h *AdminHandlers) MTLSCRL(w http.ResponseWriter, r *http.Request) {
	if h.mtlsScopeDenied(w, r) {
		return
	}
	svc := h.mtlsSvc()
	if svc == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	ca, err := svc.GetCA(ctx, id)
	if err != nil {
		http.Error(w, "CA not found", http.StatusNotFound)
		return
	}
	issued, err := svc.ListIssued(ctx, id)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	d := mtlsCRLData{baseAdminData: h.base(r, "mTLS revocation list"), CAID: id, CAName: ca.Name}
	for _, c := range issued {
		if !c.Revoked() {
			continue
		}
		row := mtlsCertRow{
			ID: c.ID, Subject: c.Subject, Serial: c.Serial,
			NotAfter: c.NotAfter.UTC().Format("2006-01-02"),
			Status:   c.Status, Revoked: true, Expired: c.Expired(),
			IssuedAt: c.IssuedAt.UTC().Format("2006-01-02"),
		}
		if c.RevokedAt.Valid {
			row.RevokedAt = c.RevokedAt.Time.UTC().Format("2006-01-02")
		}
		d.Revoked = append(d.Revoked, row)
	}
	h.render(w, "mtls_crl", d)
}

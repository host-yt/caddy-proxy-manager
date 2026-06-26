package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/manualcerts"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// manualCertRow is the display shape for one imported cert (no key material).
type manualCertRow struct {
	ID         int64
	Name       string
	CommonName string
	SANs       []string
	NotBefore  string
	NotAfter   string
	DaysLeft   int
	Status     manualcerts.ExpiryStatus
	RouteID    sql.NullInt64
}

type manualCertsData struct {
	baseAdminData
	Certs []manualCertRow
	Total int
}

// manualCertsSvc returns a ready-to-use Service or nil when deps are missing.
func (h *AdminHandlers) manualCertsSvc() *manualcerts.Service {
	if h.DB == nil || h.State == nil {
		return nil
	}
	return &manualcerts.Service{
		DB:      h.DB,
		Encrypt: h.State.Encrypt,
		Decrypt: h.State.Decrypt,
	}
}

// ManualCertsList GET /admin/manual-certs - list imported certs with expiry status.
func (h *AdminHandlers) ManualCertsList(w http.ResponseWriter, r *http.Request) {
	d := manualCertsData{baseAdminData: h.base(r, "Manual Certificates")}
	svc := h.manualCertsSvc()
	if svc == nil {
		h.render(w, "manual_certs", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	recs, err := svc.List(ctx)
	if err != nil {
		h.Logger.Error("manual certs list", "err", err)
		d.Error = "query failed"
		h.render(w, "manual_certs", d)
		return
	}
	for _, rec := range recs {
		d.Certs = append(d.Certs, manualCertRow{
			ID:         rec.ID,
			Name:       rec.Name,
			CommonName: rec.CommonName,
			SANs:       rec.SANs,
			NotBefore:  rec.NotBefore.UTC().Format("2006-01-02"),
			NotAfter:   rec.NotAfter.UTC().Format("2006-01-02"),
			DaysLeft:   rec.DaysUntilExpiry(),
			Status:     rec.Expiry(),
			RouteID:    rec.RouteID,
		})
	}
	d.Total = len(d.Certs)
	h.render(w, "manual_certs", d)
}

// ManualCertsImport POST /admin/manual-certs/import - paste + validate + store a cert.
func (h *AdminHandlers) ManualCertsImport(w http.ResponseWriter, r *http.Request) {
	const page = "/admin/manual-certs"
	svc := h.manualCertsSvc()
	if svc == nil {
		redirectWithFlash(w, r, page, "", "crypto not configured")
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectWithFlash(w, r, page, "", "form parse error")
		return
	}
	name := r.FormValue("name")
	certPEM := r.FormValue("cert_pem")
	keyPEM := r.FormValue("key_pem")
	chainPEM := r.FormValue("chain_pem")

	// Optional route association.
	var routeID sql.NullInt64
	if v := r.FormValue("route_id"); v != "" {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil && id > 0 {
			routeID = sql.NullInt64{Int64: id, Valid: true}
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	id, err := svc.Import(ctx, manualcerts.ImportInput{
		Name:     name,
		RouteID:  routeID,
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		ChainPEM: chainPEM,
	})
	if err != nil {
		redirectWithFlash(w, r, page, "", "import failed: "+err.Error())
		return
	}

	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "manual_cert.import", Entity: "manual_cert",
		EntityID: strconv.FormatInt(id, 10),
		Meta:     map[string]any{"name": name},
	})
	redirectWithFlash(w, r, page, "Certificate imported.", "")
}

// ManualCertsDelete POST /admin/manual-certs/{id}/delete.
func (h *AdminHandlers) ManualCertsDelete(w http.ResponseWriter, r *http.Request) {
	const page = "/admin/manual-certs"
	svc := h.manualCertsSvc()
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
	if err := svc.Delete(ctx, id); err != nil {
		redirectWithFlash(w, r, page, "", "delete failed: "+sanitizeErr(err))
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "manual_cert.delete", Entity: "manual_cert",
		EntityID: strconv.FormatInt(id, 10),
	})
	redirectWithFlash(w, r, page, "Certificate deleted.", "")
}

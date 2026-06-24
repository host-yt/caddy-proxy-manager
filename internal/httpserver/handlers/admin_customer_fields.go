package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/hostyt/proxy-gateway/internal/audit"
	"github.com/hostyt/proxy-gateway/internal/httpserver/middleware"
)

// CustomerFieldsView is the form-binding shape consumed by settings.html.tmpl.
type CustomerFieldsView struct {
	PhoneEnabled bool
}

// LoadCustomerFieldsView returns the current admin-controlled customer
// field visibility flags. Default = all disabled (admin opts in
// before customers can fill anything).
func (h *AdminHandlers) LoadCustomerFieldsView(ctx context.Context) CustomerFieldsView {
	db := h.DB()
	if db == nil {
		return CustomerFieldsView{}
	}
	kv := h.loadSettings(ctx, db, []string{"customer.phone_collection_enabled"})
	return CustomerFieldsView{
		PhoneEnabled: kv["customer.phone_collection_enabled"] == "1",
	}
}

// SettingsCustomerFields handles POST /admin/settings/customer-fields.
func (h *AdminHandlers) SettingsCustomerFields(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	enabled := "0"
	if r.FormValue("phone_enabled") == "1" {
		enabled = "1"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := h.saveSettings(ctx, db, map[string]string{
		"customer.phone_collection_enabled": enabled,
	}, false); err != nil {
		redirectWithFlash(w, r, "/admin/settings", "", "save failed: "+sanitizeErr(err))
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "settings.customer_fields.save", Entity: "settings",
		EntityID: "customer_fields",
		Meta:     map[string]any{"phone_enabled": enabled == "1"},
	})
	redirectWithFlash(w, r, "/admin/settings", "Customer field visibility saved.", "")
}

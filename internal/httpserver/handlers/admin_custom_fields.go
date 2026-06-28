package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/customfields"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// CustomFieldDefsJSON GET /admin/settings/custom-fields?entity=client|host
// Returns JSON {defs:[...]} for the given entity type.
func (h *AdminHandlers) CustomFieldDefsJSON(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, `{"error":"no db"}`, http.StatusServiceUnavailable)
		return
	}
	entityType := r.URL.Query().Get("entity")
	if entityType != "client" && entityType != "host" {
		entityType = "client"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	defs, err := customfields.LoadDefs(ctx, db, entityType)
	if err != nil {
		http.Error(w, `{"error":"load failed"}`, http.StatusInternalServerError)
		return
	}

	type defJSON struct {
		ID       int64    `json:"id"`
		Key      string   `json:"key"`
		Label    string   `json:"label"`
		Type     string   `json:"type"`
		Options  []string `json:"options"`
		Required bool     `json:"required"`
		Sort     int      `json:"sort"`
	}
	out := make([]defJSON, 0, len(defs))
	for _, d := range defs {
		opts := d.Options
		if opts == nil {
			opts = []string{}
		}
		out = append(out, defJSON{
			ID:       d.ID,
			Key:      d.Key,
			Label:    d.Label,
			Type:     string(d.Type),
			Options:  opts,
			Required: d.Required,
			Sort:     d.Sort,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"defs": out})
}

// CustomFieldCreate POST /admin/settings/custom-fields
func (h *AdminHandlers) CustomFieldCreate(w http.ResponseWriter, r *http.Request) {
	const page = "/admin/settings#customfields"
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()

	entityType := r.FormValue("entity_type")
	if entityType != "client" && entityType != "host" {
		redirectWithFlash(w, r, page, "", "invalid entity_type")
		return
	}
	fieldKey := strings.ToLower(strings.TrimSpace(r.FormValue("field_key")))
	if !customfields.ValidateKey(fieldKey) {
		redirectWithFlash(w, r, page, "", "field_key must match [a-z0-9_]{1,40}")
		return
	}
	label := strings.TrimSpace(r.FormValue("label"))
	if label == "" || len(label) > 120 {
		redirectWithFlash(w, r, page, "", "label required, max 120 characters")
		return
	}
	ft := customfields.FieldType(strings.TrimSpace(r.FormValue("field_type")))
	if !customfields.ValidateFieldType(ft) {
		redirectWithFlash(w, r, page, "", "unknown field_type")
		return
	}

	// Parse options for select type.
	var optionsJSON *string
	if ft == customfields.Select {
		raw := strings.TrimSpace(r.FormValue("options"))
		var opts []string
		for _, o := range strings.FieldsFunc(raw, func(c rune) bool { return c == ',' || c == '\n' }) {
			if v := strings.TrimSpace(o); v != "" {
				opts = append(opts, v)
			}
		}
		if len(opts) == 0 {
			redirectWithFlash(w, r, page, "", "select type requires at least one option")
			return
		}
		b, _ := json.Marshal(opts)
		s := string(b)
		optionsJSON = &s
	}

	required := 0
	if r.FormValue("required") == "1" || r.FormValue("required") == "on" {
		required = 1
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	_, err := db.ExecContext(ctx,
		`INSERT INTO custom_field_defs (entity_type, field_key, label, field_type, options_json, required, sort_order)
		 VALUES (?, ?, ?, ?, ?, ?, (SELECT COALESCE(MAX(sort_order),0)+1 FROM custom_field_defs AS t WHERE t.entity_type = ?))`,
		entityType, fieldKey, label, string(ft), optionsJSON, required, entityType)
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate") || strings.Contains(err.Error(), "duplicate") {
			redirectWithFlash(w, r, page, "", "field_key already exists for this entity")
			return
		}
		redirectWithFlash(w, r, page, "", "create failed: "+sanitizeErr(err))
		return
	}

	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "settings.custom_fields.create", Entity: "custom_field",
		EntityID: entityType + "." + fieldKey,
		Meta:     map[string]any{"label": label, "type": string(ft)},
	})
	redirectWithFlash(w, r, page, "Custom field created.", "")
}

// CustomFieldUpdate POST /admin/settings/custom-fields/{id}/update
func (h *AdminHandlers) CustomFieldUpdate(w http.ResponseWriter, r *http.Request) {
	const page = "/admin/settings#customfields"
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if id == 0 {
		redirectWithFlash(w, r, page, "", "invalid id")
		return
	}
	_ = r.ParseForm()

	label := strings.TrimSpace(r.FormValue("label"))
	if label == "" || len(label) > 120 {
		redirectWithFlash(w, r, page, "", "label required, max 120 characters")
		return
	}
	ft := customfields.FieldType(strings.TrimSpace(r.FormValue("field_type")))
	if !customfields.ValidateFieldType(ft) {
		redirectWithFlash(w, r, page, "", "unknown field_type")
		return
	}

	var optionsJSON *string
	if ft == customfields.Select {
		raw := strings.TrimSpace(r.FormValue("options"))
		var opts []string
		for _, o := range strings.FieldsFunc(raw, func(c rune) bool { return c == ',' || c == '\n' }) {
			if v := strings.TrimSpace(o); v != "" {
				opts = append(opts, v)
			}
		}
		if len(opts) == 0 {
			redirectWithFlash(w, r, page, "", "select type requires at least one option")
			return
		}
		b, _ := json.Marshal(opts)
		s := string(b)
		optionsJSON = &s
	}

	required := 0
	if r.FormValue("required") == "1" || r.FormValue("required") == "on" {
		required = 1
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	_, err := db.ExecContext(ctx,
		`UPDATE custom_field_defs SET label=?, field_type=?, options_json=?, required=? WHERE id=?`,
		label, string(ft), optionsJSON, required, id)
	if err != nil {
		redirectWithFlash(w, r, page, "", "update failed: "+sanitizeErr(err))
		return
	}

	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "settings.custom_fields.update", Entity: "custom_field",
		EntityID: strconv.FormatInt(id, 10),
		Meta:     map[string]any{"label": label, "type": string(ft)},
	})
	redirectWithFlash(w, r, page, "Custom field updated.", "")
}

// CustomFieldDelete POST /admin/settings/custom-fields/{id}/delete
func (h *AdminHandlers) CustomFieldDelete(w http.ResponseWriter, r *http.Request) {
	const page = "/admin/settings#customfields"
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if id == 0 {
		redirectWithFlash(w, r, page, "", "invalid id")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	_, err := db.ExecContext(ctx, "DELETE FROM custom_field_defs WHERE id = ?", id)
	if err != nil {
		redirectWithFlash(w, r, page, "", "delete failed: "+sanitizeErr(err))
		return
	}

	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "settings.custom_fields.delete", Entity: "custom_field",
		EntityID: strconv.FormatInt(id, 10),
	})
	redirectWithFlash(w, r, page, "Custom field deleted.", "")
}

// CustomFieldReorder POST /admin/settings/custom-fields/reorder
// Form: ids[] in the desired order.
func (h *AdminHandlers) CustomFieldReorder(w http.ResponseWriter, r *http.Request) {
	const page = "/admin/settings#customfields"
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()

	ids := r.Form["ids[]"]
	if len(ids) == 0 {
		redirectWithFlash(w, r, page, "", "no ids provided")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	for i, sid := range ids {
		id, _ := strconv.ParseInt(sid, 10, 64)
		if id == 0 {
			continue
		}
		_, _ = db.ExecContext(ctx, "UPDATE custom_field_defs SET sort_order=? WHERE id=?", i, id)
	}

	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "settings.custom_fields.reorder", Entity: "custom_field",
		EntityID: "reorder",
	})
	redirectWithFlash(w, r, page, "Custom fields reordered.", "")
}

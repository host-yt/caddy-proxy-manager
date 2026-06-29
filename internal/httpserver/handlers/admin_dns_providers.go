package handlers

import (
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// dnsProviderRow is the sanitized list shape: the encrypted api_token is
// never read into it, only a has-credential flag derived from the column.
type dnsProviderRow struct {
	ID       int64
	Name     string // apex zone, e.g. customer.com
	Provider string
	HasToken bool
	Created  string
}

type dnsProvidersData struct {
	baseAdminData
	Providers []dnsProviderRow
	// DNS01Available mirrors the build gate; when false the page shows a
	// warning that policies will not be emitted until the fleet is rebuilt.
	DNS01Available bool
	// Registry feeds the provider dropdown; RegistryJSON is the slug->fields
	// map the nonce'd JS uses to render only the selected provider's inputs.
	Registry     []caddyapi.DNSProvider
	RegistryJSON template.JS
}

// DNSProvidersPage GET /admin/settings/dns-providers.
func (h *AdminHandlers) DNSProvidersPage(w http.ResponseWriter, r *http.Request) {
	d := dnsProvidersData{baseAdminData: h.base(r, "DNS providers")}
	if h.Routes != nil {
		d.DNS01Available = h.Routes.DNS01ModuleAvailable
	}
	d.Registry = caddyapi.DNSProviders()
	d.RegistryJSON = dnsRegistryJSON(d.Registry)
	db := h.DB()
	if db == nil {
		h.render(w, "dns_providers", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	// Select api_token_enc != '' as a boolean only - the token itself never
	// leaves the DB layer.
	rows, err := db.QueryContext(ctx,
		`SELECT id, name, provider, (api_token_enc <> ''), DATE_FORMAT(created_at,'%Y-%m-%d')
		   FROM dns_providers ORDER BY name ASC`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var p dnsProviderRow
			if err := rows.Scan(&p.ID, &p.Name, &p.Provider, &p.HasToken, &p.Created); err == nil {
				d.Providers = append(d.Providers, p)
			}
		}
	}
	h.render(w, "dns_providers", d)
}

// DNSProvidersCreate POST /admin/settings/dns-providers. Stores the api_token
// AES-256-GCM encrypted; the plaintext is read once and never persisted or
// logged in the clear.
func (h *AdminHandlers) DNSProvidersCreate(w http.ResponseWriter, r *http.Request) {
	const page = "/admin/settings/dns-providers"
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	if h.Routes == nil || h.Routes.EncryptSecret == nil {
		redirectWithFlash(w, r, page, "", "secret encryption not configured")
		return
	}
	_ = r.ParseForm()
	name := strings.ToLower(strings.TrimSpace(r.FormValue("name")))
	provider := strings.ToLower(strings.TrimSpace(r.FormValue("provider")))
	if provider == "" {
		provider = "cloudflare"
	}
	p, ok := caddyapi.DNSProviderBySlug(provider)
	if !ok {
		redirectWithFlash(w, r, page, "", "unsupported DNS provider")
		return
	}
	if name == "" || !isHostname(name) {
		redirectWithFlash(w, r, page, "", "zone must be a valid apex domain")
		return
	}
	// Collect this provider's fields (form names are prefixed to avoid clashes).
	raw := make(map[string]string, len(p.Fields))
	for _, f := range p.Fields {
		raw[f.Key] = r.FormValue("field_" + f.Key)
	}
	fields, err := caddyapi.ValidateDNSFields(provider, raw)
	if err != nil {
		redirectWithFlash(w, r, page, "", "all required credential fields are needed")
		return
	}
	blob, err := caddyapi.EncodeDNSFields(fields)
	if err != nil {
		redirectWithFlash(w, r, page, "", "credential encode failed")
		return
	}
	enc, err := h.Routes.EncryptSecret(blob)
	if err != nil {
		redirectWithFlash(w, r, page, "", "credential encrypt failed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	// Upsert on the unique zone so re-saving a zone rotates its credential.
	var dnsQ string
	if store.Driver() == "sqlite3" {
		dnsQ = `INSERT INTO dns_providers (name, provider, api_token_enc) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET provider=excluded.provider, api_token_enc=excluded.api_token_enc`
	} else {
		dnsQ = `INSERT INTO dns_providers (name, provider, api_token_enc) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE provider=VALUES(provider), api_token_enc=VALUES(api_token_enc)`
	}
	if _, err := db.ExecContext(ctx, dnsQ, name, provider, enc); err != nil {
		redirectWithFlash(w, r, page, "", "save failed: "+sanitizeErr(err))
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "dns_provider.save", Entity: "dns_provider",
		EntityID: name, Meta: map[string]any{"provider": provider}, // never the token
	})
	redirectWithFlash(w, r, page, "DNS provider saved.", "")
}

// DNSProvidersDelete POST /admin/settings/dns-providers/{id}/delete.
func (h *AdminHandlers) DNSProvidersDelete(w http.ResponseWriter, r *http.Request) {
	const page = "/admin/settings/dns-providers"
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx, "DELETE FROM dns_providers WHERE id = ?", id); err != nil {
		redirectWithFlash(w, r, page, "", "delete failed: "+sanitizeErr(err))
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "dns_provider.delete", Entity: "dns_provider",
		EntityID: strconv.FormatInt(id, 10),
	})
	redirectWithFlash(w, r, page, "DNS provider deleted.", "")
}

// dnsRegistryJSON emits the provider field SCHEMA (slug -> fields) for the
// page JS - no credentials, only key/label/placeholder/secret/optional - so
// the handler shows the right inputs per selected provider.
func dnsRegistryJSON(reg []caddyapi.DNSProvider) template.JS {
	type fld struct {
		Key         string `json:"key"`
		Label       string `json:"label"`
		Placeholder string `json:"placeholder,omitempty"`
		Secret      bool   `json:"secret"`
		Optional    bool   `json:"optional"`
	}
	m := make(map[string][]fld, len(reg))
	for _, p := range reg {
		fs := make([]fld, 0, len(p.Fields))
		for _, f := range p.Fields {
			fs = append(fs, fld{f.Key, f.Label, f.Placeholder, f.Secret, f.Optional})
		}
		m[p.Slug] = fs
	}
	b, err := json.Marshal(m)
	if err != nil {
		return template.JS("{}")
	}
	return template.JS(b)
}

// isHostname does a cheap apex-domain sanity check (letters/digits/hyphen
// labels, at least one dot). Not a full RFC validator; the cert issuance
// itself rejects bad zones.
func isHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

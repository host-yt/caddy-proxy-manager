package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/domain/routes"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// npmBackup is the minimal shape we parse from an NPM JSON export.
type npmBackup struct {
	ProxyHosts []npmProxyHost `json:"proxy_hosts"`
}

type npmProxyHost struct {
	DomainNames   []string `json:"domain_names"`
	ForwardScheme string   `json:"forward_scheme"`
	ForwardHost   string   `json:"forward_host"`
	ForwardPort   int      `json:"forward_port"`
	SSLForced     bool     `json:"ssl_forced"`
	HTTP2Support  bool     `json:"http2_support"`
	Enabled       int      `json:"enabled"` // 0 or 1 in NPM JSON
}

// npmImportResult is the JSON response body returned to the client.
type npmImportResult struct {
	Imported int      `json:"imported"`
	Skipped  int      `json:"skipped"`
	Errors   []string `json:"errors"`
}

// npmImportPageData is the template data for GET /admin/tools/npm-import.
type npmImportPageData struct {
	baseAdminData
	Result *npmImportResult // non-nil after a successful POST (for page redirect result display)
}

// NpmImportPage renders GET /admin/tools/npm-import.
func (h *AdminHandlers) NpmImportPage(w http.ResponseWriter, r *http.Request) {
	d := npmImportPageData{baseAdminData: h.base(r, "NPM Import")}
	h.render(w, "npm_import", d)
}

// NpmImportSubmit handles POST /admin/tools/npm-import.
// Accepts multipart form with a single "file" field containing an NPM JSON backup.
// Returns JSON: {imported, skipped, errors}.
func (h *AdminHandlers) NpmImportSubmit(w http.ResponseWriter, r *http.Request) {
	// 32 MB cap - NPM backups are small JSON files.
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		jsonErr(w, "invalid multipart form", http.StatusBadRequest)
		return
	}

	f, _, err := r.FormFile("file")
	if err != nil {
		jsonErr(w, "file field missing", http.StatusBadRequest)
		return
	}
	defer f.Close()

	raw, err := io.ReadAll(io.LimitReader(f, 32<<20))
	if err != nil {
		jsonErr(w, "read error", http.StatusInternalServerError)
		return
	}

	var backup npmBackup
	if err := json.Unmarshal(raw, &backup); err != nil {
		jsonErr(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	result := h.runNpmImport(r, backup.ProxyHosts)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}

// runNpmImport processes each proxy_host entry and returns the aggregated result.
func (h *AdminHandlers) runNpmImport(r *http.Request, hosts []npmProxyHost) npmImportResult {
	result := npmImportResult{Errors: []string{}}

	db := h.DB()
	if db == nil {
		result.Errors = append(result.Errors, "database unavailable")
		return result
	}
	if h.Routes == nil {
		result.Errors = append(result.Errors, "route service not wired")
		return result
	}

	sess := middleware.SessionFromContext(r.Context())
	if sess == nil {
		result.Errors = append(result.Errors, "session missing")
		return result
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	// Resolve the caller's admin client once; shared across all imports.
	clientID, err := ensureAdminClient(ctx, db, sess.UserID)
	if err != nil {
		result.Errors = append(result.Errors, "admin client setup: "+err.Error())
		return result
	}

	// Pick the first enabled + approved node to derive a node group for the
	// admin plan. The route service will re-pick the best node per Create call.
	var nodeGroupID int64
	if err := db.QueryRowContext(ctx,
		"SELECT node_group_id FROM caddy_nodes WHERE approved_at IS NOT NULL AND is_enabled = 1 ORDER BY id ASC LIMIT 1",
	).Scan(&nodeGroupID); err != nil {
		result.Errors = append(result.Errors, "no available node: "+err.Error())
		return result
	}

	planID, err := ensureAdminPlan(ctx, db, nodeGroupID)
	if err != nil {
		result.Errors = append(result.Errors, "admin plan setup: "+err.Error())
		return result
	}

	for _, ph := range hosts {
		if ph.Enabled == 0 {
			result.Skipped++
			continue
		}
		if ph.ForwardHost == "" || ph.ForwardPort <= 0 {
			result.Skipped++
			continue
		}

		scheme := ph.ForwardScheme
		if scheme != "https" {
			scheme = "http"
		}

		// One service per upstream backend (matches existing admin convention).
		backendIP := ph.ForwardHost
		serviceID, err := ensureAdminService(ctx, db, clientID, backendIP, planID, nodeGroupID)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("service for %s: %s", backendIP, err))
			result.Skipped++
			continue
		}

		for _, domain := range ph.DomainNames {
			if domain == "" {
				result.Skipped++
				continue
			}
			in := routes.CreateInput{
				ServiceID:      serviceID,
				Domain:         domain,
				UpstreamScheme: scheme,
				UpstreamPort:   ph.ForwardPort,
				SSL:            ph.SSLForced,
				ForceHTTPS:     ph.SSLForced,
				WebSocket:      true, // safe default; can be toggled later
				Kind:           "proxy",
				Tag:            "npm-import",
			}
			if _, err := h.Routes.Create(ctx, 0, in); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %s", domain, err))
				result.Skipped++
				continue
			}
			result.Imported++
		}
	}

	return result
}

// jsonErr writes a JSON error body with the given status code.
func jsonErr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

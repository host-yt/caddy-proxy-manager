package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/domain/routes"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// npmBackup is the shape we parse from an NPM "Full Backup" JSON export.
// Everything the panel cannot reproduce is still parsed, so the report can say
// what an operator has to carry over by hand instead of silently dropping it.
type npmBackup struct {
	ProxyHosts       []npmProxyHost    `json:"proxy_hosts"`
	RedirectionHosts []npmRedirectHost `json:"redirection_hosts"`
	DeadHosts        []npmDeadHost     `json:"dead_hosts"`
	Streams          []npmStream       `json:"streams"`
	AccessLists      []npmAccessList   `json:"access_lists"`
	Certificates     []npmCertificate  `json:"certificates"`
}

type npmProxyHost struct {
	DomainNames    []string      `json:"domain_names"`
	ForwardScheme  string        `json:"forward_scheme"`
	ForwardHost    string        `json:"forward_host"`
	ForwardPort    int           `json:"forward_port"`
	SSLForced      bool          `json:"ssl_forced"`
	HTTP2Support   bool          `json:"http2_support"`
	HSTSEnabled    bool          `json:"hsts_enabled"`
	CachingEnabled bool          `json:"caching_enabled"`
	BlockExploits  bool          `json:"block_exploits"`
	AllowWebsocket bool          `json:"allow_websocket_upgrade"`
	AccessListID   int64         `json:"access_list_id"`
	CertificateID  json.Number   `json:"certificate_id"`
	AdvancedConfig string        `json:"advanced_config"`
	Locations      []npmLocation `json:"locations"`
	Enabled        int           `json:"enabled"` // 0 or 1 in NPM JSON
}

type npmLocation struct {
	Path           string `json:"path"`
	ForwardScheme  string `json:"forward_scheme"`
	ForwardHost    string `json:"forward_host"`
	ForwardPort    int    `json:"forward_port"`
	AdvancedConfig string `json:"advanced_config"`
}

type npmRedirectHost struct {
	DomainNames       []string `json:"domain_names"`
	ForwardScheme     string   `json:"forward_scheme"` // auto | http | https
	ForwardDomainName string   `json:"forward_domain_name"`
	ForwardHTTPCode   int      `json:"forward_http_code"`
	PreservePath      bool     `json:"preserve_path"`
	SSLForced         bool     `json:"ssl_forced"`
	AdvancedConfig    string   `json:"advanced_config"`
	Enabled           int      `json:"enabled"`
}

type npmDeadHost struct {
	DomainNames []string `json:"domain_names"`
	Enabled     int      `json:"enabled"`
}

type npmStream struct {
	IncomingPort   int    `json:"incoming_port"`
	ForwardingHost string `json:"forwarding_host"`
	ForwardingPort int    `json:"forwarding_port"`
	TCPForwarding  bool   `json:"tcp_forwarding"`
	UDPForwarding  bool   `json:"udp_forwarding"`
	Enabled        int    `json:"enabled"`
}

type npmAccessList struct {
	Name       string `json:"name"`
	SatisfyAny bool   `json:"satisfy_any"`
	Items      []struct {
		Username string `json:"username"`
	} `json:"items"`
	Clients []struct {
		Address   string `json:"address"`
		Directive string `json:"directive"`
	} `json:"clients"`
}

type npmCertificate struct {
	Provider    string   `json:"provider"` // letsencrypt | other
	NiceName    string   `json:"nice_name"`
	DomainNames []string `json:"domain_names"`
}

// Actions an entry in the report can carry.
const (
	npmActionImported = "imported" // written (or, in a dry run, would be)
	npmActionSkipped  = "skipped"  // nothing to do: disabled, duplicate, invalid
	npmActionManual   = "manual"   // recognised, not reproducible: carry over by hand
)

// npmImportItem is one line of the report.
type npmImportItem struct {
	Kind   string `json:"kind"`   // proxy host, redirect, stream, ...
	Name   string `json:"name"`   // domain, or another identifier for the entry
	Action string `json:"action"` // imported | skipped | manual
	Detail string `json:"detail"` // why, in one line
}

// npmImportResult is the JSON response body returned to the client.
type npmImportResult struct {
	// DryRun means nothing was written: every "imported" line is what the real
	// run would do.
	DryRun   bool            `json:"dry_run"`
	Imported int             `json:"imported"`
	Skipped  int             `json:"skipped"`
	Manual   int             `json:"manual"`
	Items    []npmImportItem `json:"items"`
	Errors   []string        `json:"errors"`
}

func (res *npmImportResult) add(kind, name, action, detail string) {
	switch action {
	case npmActionImported:
		res.Imported++
	case npmActionSkipped:
		res.Skipped++
	case npmActionManual:
		res.Manual++
	}
	// Bound the report: a huge backup should not produce a megabyte of JSON.
	if len(res.Items) < npmMaxReportItems {
		res.Items = append(res.Items, npmImportItem{Kind: kind, Name: name, Action: action, Detail: detail})
	}
}

// npmMaxReportItems caps the per-entry report; the counters stay exact.
const npmMaxReportItems = 2000

// npmImportPageData is the template data for GET /admin/tools/npm-import.
type npmImportPageData struct {
	baseAdminData
	Result *npmImportResult // non-nil after a successful POST (for page redirect result display)
}

// npmImportMaxBytes bounds the entire upload (body, not just the in-memory
// part of the multipart form). NPM backups are small JSON files; 33 MB leaves
// slack over the 32 MB in-memory cap for multipart framing.
const npmImportMaxBytes = 33 << 20

// NpmImportPage renders GET /admin/tools/npm-import.
func (h *AdminHandlers) NpmImportPage(w http.ResponseWriter, r *http.Request) {
	d := npmImportPageData{baseAdminData: h.base(r, "NPM Import")}
	h.render(w, "npm_import", d)
}

// NpmImportSubmit handles POST /admin/tools/npm-import.
// Accepts a multipart form with a "file" field containing an NPM JSON backup
// and an optional "dry_run" field. Returns the JSON report.
func (h *AdminHandlers) NpmImportSubmit(w http.ResponseWriter, r *http.Request) {
	// Cap the whole request first. ParseMultipartForm's argument only bounds
	// what is kept in memory - everything above it spills to a temp file with
	// no limit, so without this a single upload can fill the panel's disk.
	r.Body = http.MaxBytesReader(w, r.Body, npmImportMaxBytes)
	// 32 MB in-memory cap - NPM backups are small JSON files.
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		jsonErr(w, "invalid or oversized multipart form (max 33 MB)", http.StatusBadRequest)
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll() // drop any spill file promptly
		}
	}()

	dryRun := r.FormValue("dry_run") == "1"

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
		h.Logger.Warn("npm import: invalid JSON", "err", err)
		jsonErr(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	result := h.runNpmImport(r, backup, dryRun)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}

// runNpmImport walks the backup and returns the report. With dryRun set it
// performs every check - SSRF screening, domain conflicts, node availability -
// and writes nothing, so an operator can see exactly what a real import would
// do, and what it cannot carry over, before committing to it.
func (h *AdminHandlers) runNpmImport(r *http.Request, backup npmBackup, dryRun bool) npmImportResult {
	result := npmImportResult{DryRun: dryRun, Errors: []string{}, Items: []npmImportItem{}}

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

	// Everything the panel has no equivalent for is reported first, so the
	// operator sees the whole picture even if a later route write fails.
	reportUnsupported(&result, backup)

	var (
		clientID    int64
		planID      int64
		nodeGroupID int64
		err         error
	)
	// A dry run still needs the node lookup to say whether an import is
	// possible at all, but must not create the admin client/plan/service rows
	// a real import would.
	if !dryRun {
		clientID, err = ensureAdminClient(ctx, db, sess.UserID, sess.ResellerID)
		if err != nil {
			h.Logger.Warn("npm import: admin client setup failed", "err", err)
			result.Errors = append(result.Errors, "admin client setup failed")
			return result
		}
	}
	// Pick the first enabled + approved node to derive a node group for the
	// admin plan. The route service will re-pick the best node per Create call.
	if err := db.QueryRowContext(ctx,
		"SELECT node_group_id FROM caddy_nodes WHERE approved_at IS NOT NULL AND is_enabled = 1 ORDER BY id ASC LIMIT 1",
	).Scan(&nodeGroupID); err != nil {
		h.Logger.Warn("npm import: no available node", "err", err)
		result.Errors = append(result.Errors, "no available node")
		return result
	}
	if !dryRun {
		planID, err = ensureAdminPlan(ctx, db, nodeGroupID)
		if err != nil {
			h.Logger.Warn("npm import: admin plan setup failed", "err", err)
			result.Errors = append(result.Errors, "admin plan setup failed")
			return result
		}
	}

	h.importProxyHosts(ctx, db, &result, backup.ProxyHosts, clientID, planID, nodeGroupID, dryRun)
	h.importRedirects(ctx, db, &result, backup.RedirectionHosts, clientID, planID, nodeGroupID, dryRun)
	return result
}

// importProxyHosts imports (or, in a dry run, plans) every enabled proxy host.
func (h *AdminHandlers) importProxyHosts(ctx context.Context, db *sql.DB, result *npmImportResult,
	hosts []npmProxyHost, clientID, planID, nodeGroupID int64, dryRun bool) {
	const kind = "proxy host"
	for _, ph := range hosts {
		name := strings.Join(ph.DomainNames, ", ")
		if ph.Enabled == 0 {
			result.add(kind, name, npmActionSkipped, "disabled in NPM")
			continue
		}
		if ph.ForwardHost == "" || ph.ForwardPort <= 0 {
			result.add(kind, name, npmActionSkipped, "no forward host/port")
			continue
		}
		// SSRF: refuse forward hosts that resolve to loopback/link-local/metadata.
		if err := screenBackendHost(ctx, ph.ForwardHost); err != nil {
			result.add(kind, name, npmActionSkipped, fmt.Sprintf("forward host %s rejected: %s", ph.ForwardHost, err))
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %s", ph.ForwardHost, err))
			continue
		}
		// Per-host settings the panel expresses differently, or not at all.
		for _, note := range proxyHostNotes(ph) {
			result.add(kind, name, npmActionManual, note)
		}

		scheme := ph.ForwardScheme
		if scheme != "https" {
			scheme = "http"
		}

		var serviceID int64
		if !dryRun {
			// One service per upstream backend (matches existing admin convention).
			id, err := ensureAdminService(ctx, db, clientID, ph.ForwardHost, planID, nodeGroupID)
			if err != nil {
				result.add(kind, name, npmActionSkipped, "service create failed")
				result.Errors = append(result.Errors, fmt.Sprintf("service for %s: %s", ph.ForwardHost, err))
				continue
			}
			serviceID = id
		}

		for _, domain := range ph.DomainNames {
			if domain == "" {
				result.add(kind, "(empty)", npmActionSkipped, "empty domain name")
				continue
			}
			if dryRun {
				if domainAlreadyMapped(ctx, db, domain) {
					result.add(kind, domain, npmActionSkipped, "domain already mapped in this panel")
					continue
				}
				result.add(kind, domain, npmActionImported,
					fmt.Sprintf("would proxy to %s://%s:%d", scheme, ph.ForwardHost, ph.ForwardPort))
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
				result.add(kind, domain, npmActionSkipped, err.Error())
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %s", domain, err))
				continue
			}
			result.add(kind, domain, npmActionImported,
				fmt.Sprintf("proxy to %s://%s:%d", scheme, ph.ForwardHost, ph.ForwardPort))
		}
	}
}

// importRedirects carries NPM redirection hosts over as redirect routes.
func (h *AdminHandlers) importRedirects(ctx context.Context, db *sql.DB, result *npmImportResult,
	hosts []npmRedirectHost, clientID, planID, nodeGroupID int64, dryRun bool) {
	const kind = "redirect"
	for _, rh := range hosts {
		name := strings.Join(rh.DomainNames, ", ")
		if rh.Enabled == 0 {
			result.add(kind, name, npmActionSkipped, "disabled in NPM")
			continue
		}
		target := strings.TrimSpace(rh.ForwardDomainName)
		if target == "" {
			result.add(kind, name, npmActionSkipped, "no forward domain")
			continue
		}
		scheme := rh.ForwardScheme
		if scheme != "http" && scheme != "https" {
			// NPM's "auto" keeps the request's scheme; the panel emits a fixed
			// Location, so https is the safe reading.
			scheme = "https"
		}
		code := rh.ForwardHTTPCode
		switch code {
		case 301, 302, 307, 308:
		default:
			code = 301
		}
		if rh.PreservePath {
			result.add(kind, name, npmActionManual,
				"NPM preserved the request path here; the panel emits a fixed Location, so the path is dropped")
		}
		if strings.TrimSpace(rh.AdvancedConfig) != "" {
			result.add(kind, name, npmActionManual, "has advanced_config (raw nginx) - re-express it as route settings")
		}

		var serviceID int64
		if !dryRun {
			// A redirect route never dials an upstream, but every route hangs
			// off a service; key it on the redirect target so a repeated import
			// reuses one row.
			id, err := ensureAdminService(ctx, db, clientID, target, planID, nodeGroupID)
			if err != nil {
				result.add(kind, name, npmActionSkipped, "service create failed")
				result.Errors = append(result.Errors, fmt.Sprintf("service for %s: %s", target, err))
				continue
			}
			serviceID = id
		}

		for _, domain := range rh.DomainNames {
			if domain == "" {
				continue
			}
			dest := scheme + "://" + target
			if dryRun {
				if domainAlreadyMapped(ctx, db, domain) {
					result.add(kind, domain, npmActionSkipped, "domain already mapped in this panel")
					continue
				}
				result.add(kind, domain, npmActionImported, fmt.Sprintf("would redirect %d to %s", code, dest))
				continue
			}
			in := routes.CreateInput{
				ServiceID:    serviceID,
				Domain:       domain,
				Kind:         "redirect",
				RedirectURL:  dest,
				RedirectCode: code,
				SSL:          rh.SSLForced,
				ForceHTTPS:   rh.SSLForced,
				Tag:          "npm-import",
			}
			if _, err := h.Routes.Create(ctx, 0, in); err != nil {
				result.add(kind, domain, npmActionSkipped, err.Error())
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %s", domain, err))
				continue
			}
			result.add(kind, domain, npmActionImported, fmt.Sprintf("redirect %d to %s", code, dest))
		}
	}
}

// proxyHostNotes lists the per-host NPM settings this importer cannot carry
// over, so they show up as "manual" lines instead of vanishing.
func proxyHostNotes(ph npmProxyHost) []string {
	var out []string
	if strings.TrimSpace(ph.AdvancedConfig) != "" {
		out = append(out, "has advanced_config (raw nginx) - re-express it as route settings or allow-listed Caddy JSON")
	}
	if len(ph.Locations) > 0 {
		out = append(out, fmt.Sprintf("has %d location rule(s) - recreate them as path-prefixed routes or location rules", len(ph.Locations)))
	}
	if ph.AccessListID > 0 {
		out = append(out, "protected by an NPM access list - recreate as basic auth, an IP allow-list or the access portal")
	}
	if certID := strings.TrimSpace(ph.CertificateID.String()); certID != "" && certID != "0" {
		out = append(out, "used a specific NPM certificate - the panel issues its own via ACME; import the key pair under Manual certs if it must be reused")
	}
	if ph.CachingEnabled {
		out = append(out, "had NPM asset caching on - enable the route's cache explicitly (it is opt-in and only for public content)")
	}
	if ph.BlockExploits {
		out = append(out, "had NPM's block-common-exploits on - the nearest equivalent is the per-route WAF")
	}
	if ph.HSTSEnabled {
		out = append(out, "had HSTS on - set it as a custom response header on the route")
	}
	return out
}

// reportUnsupported records the backup sections this importer does not write.
func reportUnsupported(result *npmImportResult, backup npmBackup) {
	for _, s := range backup.Streams {
		if s.Enabled == 0 {
			continue
		}
		proto := "tcp"
		switch {
		case s.UDPForwarding && s.TCPForwarding:
			proto = "tcp+udp"
		case s.UDPForwarding:
			proto = "udp"
		}
		result.add("stream", fmt.Sprintf(":%d", s.IncomingPort), npmActionManual,
			fmt.Sprintf("recreate as an L4 stream (%s) to %s:%d", proto, s.ForwardingHost, s.ForwardingPort))
	}
	for _, a := range backup.AccessLists {
		result.add("access list", a.Name, npmActionManual,
			fmt.Sprintf("%d user(s), %d client rule(s) - recreate as basic auth or an IP allow-list", len(a.Items), len(a.Clients)))
	}
	for _, c := range backup.Certificates {
		if c.Provider == "letsencrypt" {
			continue // the panel issues these itself
		}
		name := c.NiceName
		if name == "" {
			name = strings.Join(c.DomainNames, ", ")
		}
		result.add("certificate", name, npmActionManual,
			"custom certificate - import the key pair under Manual certs and link it to the route")
	}
	for _, d := range backup.DeadHosts {
		if d.Enabled == 0 {
			continue
		}
		result.add("404 host", strings.Join(d.DomainNames, ", "), npmActionManual,
			"NPM 404 host - recreate as a route in maintenance mode, or a redirect")
	}
}

// domainAlreadyMapped reports whether a route already serves this domain.
// The dry run uses it to predict the duplicate-domain rejection.
func domainAlreadyMapped(ctx context.Context, db *sql.DB, domain string) bool {
	var n int
	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM routes WHERE domain = ?", strings.ToLower(strings.TrimSpace(domain)),
	).Scan(&n); err != nil {
		return false
	}
	return n > 0
}

// jsonErr writes a JSON error body with the given status code.
func jsonErr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

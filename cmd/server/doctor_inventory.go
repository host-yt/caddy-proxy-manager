// R0.3: read-only inventory of routes already stored that would not pass
// today's write-path policies. Every fix so far only blocks NEW bad writes;
// this reports what is already in the database so an operator can act on it.
// Never mutates - pure SELECT + in-process screening against the exported
// policy functions the write/emission path already uses.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
	"github.com/host-yt/caddy-proxy-manager/internal/streamguard"
)

// inventoryShowLimit caps how many offending rows are named per check row,
// same pattern as doctorSSORoutes: enough to act on, not a log dump.
const inventoryShowLimit = 15

// doctorStoredRoutesInventory audits rows already in `routes` (and its
// location-rule/client side tables) against the policies enforced on the
// write path today. Read-only: it reports, it never edits a row.
func doctorStoredRoutesInventory(ctx context.Context, db *sql.DB) []check {
	if db == nil {
		return nil
	}
	infra, err := streamguard.LoadInfraTargets(ctx, db)
	if err != nil {
		// Fail visibly rather than silently skipping - a clean report here
		// must mean "checked", not "could not check".
		return []check{{"routes: stored target/placeholder/WAF inventory", statusFail,
			"could not load the infra deny set, inventory not run: " + err.Error()}}
	}

	var checks []check
	checks = append(checks, doctorStoredTargets(ctx, db, infra)...)
	checks = append(checks, doctorStoredPlaceholders(ctx, db)...)
	checks = append(checks, doctorStoredWAF(ctx, db)...)
	return checks
}

// inventoryHit is one policy violation found in stored data.
type inventoryHit struct {
	routeID int64
	client  string
	service string
	reason  string
}

func (h inventoryHit) String() string {
	return fmt.Sprintf("route #%d (%s / %s): %s", h.routeID, h.client, h.service, h.reason)
}

// summarizeHits turns a list of violations into one check row, capped so the
// table stays readable; the count in the detail always reflects the true total.
func summarizeHits(name string, hits []inventoryHit) check {
	if len(hits) == 0 {
		return check{name, statusPass, "no stored rows violate today's policy"}
	}
	shown := hits
	extra := 0
	if len(shown) > inventoryShowLimit {
		extra = len(shown) - inventoryShowLimit
		shown = shown[:inventoryShowLimit]
	}
	lines := make([]string, len(shown))
	for i, h := range shown {
		lines[i] = h.String()
	}
	detail := fmt.Sprintf("%d row(s): %s", len(hits), strings.Join(lines, "; "))
	if extra > 0 {
		detail += fmt.Sprintf("; and %d more", extra)
	}
	return check{name, statusWarn, detail}
}

// hostTarget is one HTTP dial target pulled out of stored routes for screening.
type hostTarget struct {
	routeID int64
	client  string
	service string
	part    string // "primary backend", "location rule <path>"
	host    string
	port    int
}

// doctorStoredTargets screens every stored HTTP dial target - primary backend
// and location-rule backends - against the same literal (no-DNS) policy the
// emission path applies to a name it cannot resolve here: loopback/link-local,
// managed node addresses, the WireGuard control-plane mesh, and port 2019.
// DNS is deliberately never dialed from doctor - see the DNS-target row below.
func doctorStoredTargets(ctx context.Context, db *sql.DB, infra *streamguard.InfraTargets) []check {
	qCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	var targets []hostTarget

	// Primary backend: same effective-host precedence as buildRoutesForNode
	// (backend_ip_override > WG peer assigned_ip > service backend_ip), but
	// joined directly on the peer id rather than its peer_group fan-out -
	// good enough for an inventory pass; fan-out siblings sit in the same WG
	// customer subnet, a different concern from the loopback/node/2019 class
	// this check targets.
	rows, err := db.QueryContext(qCtx, `
		SELECT r.id, COALESCE(cl.display_name,''), COALESCE(sv.name,''), r.upstream_port,
		       COALESCE(NULLIF(r.backend_ip_override,''), p.assigned_ip, sv.backend_ip)
		  FROM routes r
		  JOIN services sv ON sv.id = r.service_id
		  LEFT JOIN clients cl ON cl.id = sv.client_id
		  LEFT JOIN customer_wg_peer p ON p.id = r.via_wg_peer_id
		 ORDER BY r.id`)
	if err != nil {
		return []check{{"routes: stored HTTP targets", statusFail, "query failed: " + err.Error()}}
	}
	func() {
		defer rows.Close()
		for rows.Next() {
			var t hostTarget
			var host sql.NullString
			if err := rows.Scan(&t.routeID, &t.client, &t.service, &t.port, &host); err != nil {
				continue
			}
			t.part = "primary backend"
			t.host = strings.TrimSpace(host.String)
			if t.host != "" {
				targets = append(targets, t)
			}
		}
	}()

	lrows, err := db.QueryContext(qCtx, `
		SELECT r.id, COALESCE(cl.display_name,''), COALESCE(sv.name,''),
		       lr.path_glob, COALESCE(lr.upstream_host,''), COALESCE(lr.upstream_port,0)
		  FROM route_location_rules lr
		  JOIN routes r ON r.id = lr.route_id
		  JOIN services sv ON sv.id = r.service_id
		  LEFT JOIN clients cl ON cl.id = sv.client_id
		 WHERE lr.action = 'proxy' AND COALESCE(lr.upstream_host,'') <> ''
		 ORDER BY r.id`)
	if err != nil {
		// Older schema without location rules, or a transient error either
		// way: the primary-backend check above still ran, report and move on.
		return append(checksFromTargets(infra, targets), check{"routes: stored location-rule targets", statusWarn,
			"query failed, this check was skipped: " + err.Error()})
	}
	func() {
		defer lrows.Close()
		for lrows.Next() {
			var t hostTarget
			var path string
			if err := lrows.Scan(&t.routeID, &t.client, &t.service, &path, &t.host, &t.port); err != nil {
				continue
			}
			t.part = "location rule " + path
			targets = append(targets, t)
		}
	}()

	return checksFromTargets(infra, targets)
}

// checksFromTargets applies the literal screen to every collected target and
// splits the result into a violations row and an honesty row: DNS is never
// dialed here, so a hostname target that isn't on the literal deny list is
// reported as unverified, not silently declared clean.
func checksFromTargets(infra *streamguard.InfraTargets, targets []hostTarget) []check {
	var hits []inventoryHit
	var unverified int
	for _, t := range targets {
		if looksLikeLoopbackName(t.host) {
			hits = append(hits, inventoryHit{t.routeID, t.client, t.service, t.part + " host " + t.host + " is a loopback literal"})
			continue
		}
		if err := infra.ScreenHTTPTargetLiteral(t.host, t.port); err != nil {
			hits = append(hits, inventoryHit{t.routeID, t.client, t.service, t.part + " " + t.host + ": " + err.Error()})
			continue
		}
		if net.ParseIP(t.host) == nil {
			// Hostname, not an IP literal: the literal screen cannot see what
			// it resolves to and this pass never dials DNS.
			unverified++
		}
	}
	out := []check{summarizeHits("routes: stored HTTP targets (loopback/managed-node/WG/port 2019)", hits)}
	if unverified > 0 {
		out = append(out, check{"routes: stored HTTP targets (hostname, DNS not checked)", statusWarn,
			fmt.Sprintf("%d target(s) are hostnames this read-only pass does not resolve - "+
				"a clean result above does not clear them; they are screened with a live DNS lookup at the next config push", unverified)})
	}
	return out
}

// looksLikeLoopbackName catches the common literal loopback hostnames the
// deny-set (IP/CIDR based) cannot: it only sees addresses, not names that
// happen to mean "this machine" wherever Caddy resolves them.
func looksLikeLoopbackName(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	return h == "localhost" || strings.HasSuffix(h, ".localhost") || h == "localhost.localdomain"
}

// doctorStoredPlaceholders screens every tenant-editable templated field
// already stored - route redirect/rewrite targets, upstream host header,
// custom headers, rate-limit key, and the per-client geo-block redirect -
// against the same allow-list ScreenTenantTemplate/ScreenReplacerValue enforce
// on the write path (internal/caddyapi/tenanttemplate.go TenantTemplateQuarantine).
func doctorStoredPlaceholders(ctx context.Context, db *sql.DB) []check {
	qCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var hits []inventoryHit

	rows, err := db.QueryContext(qCtx, `
		SELECT r.id, COALESCE(cl.display_name,''), COALESCE(sv.name,''),
		       COALESCE(r.redirect_url,''), COALESCE(r.upstream_host_header,''),
		       COALESCE(r.custom_headers,''), COALESCE(r.rate_key,'')
		  FROM routes r
		  JOIN services sv ON sv.id = r.service_id
		  LEFT JOIN clients cl ON cl.id = sv.client_id
		 ORDER BY r.id`)
	if err != nil {
		return []check{{"routes: stored placeholder allow-list", statusFail, "query failed: " + err.Error()}}
	}
	func() {
		defer rows.Close()
		for rows.Next() {
			var id int64
			var client, service, redirectURL, hostHeader, headersJSON, rateKey string
			if err := rows.Scan(&id, &client, &service, &redirectURL, &hostHeader, &headersJSON, &rateKey); err != nil {
				continue
			}
			checkField := func(what, v string) {
				if v == "" {
					return
				}
				if err := caddyapi.ScreenTenantTemplate(v); err != nil {
					hits = append(hits, inventoryHit{id, client, service, what + ": " + err.Error()})
				}
			}
			checkField("redirect_url", redirectURL)
			checkField("upstream_host_header", hostHeader)
			if headersJSON != "" {
				var headers map[string]string
				if json.Unmarshal([]byte(headersJSON), &headers) == nil {
					for k, v := range headers {
						checkField("custom header "+k, k+": "+v)
					}
				}
			}
			if rateKey != "" {
				if err := caddyapi.ScreenReplacerValue(rateKey); err != nil {
					hits = append(hits, inventoryHit{id, client, service, "rate_key: " + err.Error()})
				}
			}
		}
	}()

	lrows, err := db.QueryContext(qCtx, `
		SELECT r.id, COALESCE(cl.display_name,''), COALESCE(sv.name,''),
		       lr.path_glob, COALESCE(lr.redirect_url,''), COALESCE(lr.rewrite_uri,'')
		  FROM route_location_rules lr
		  JOIN routes r ON r.id = lr.route_id
		  JOIN services sv ON sv.id = r.service_id
		  LEFT JOIN clients cl ON cl.id = sv.client_id
		 ORDER BY r.id`)
	if err == nil {
		defer lrows.Close()
		for lrows.Next() {
			var id int64
			var client, service, path, redirectURL, rewriteURI string
			if err := lrows.Scan(&id, &client, &service, &path, &redirectURL, &rewriteURI); err != nil {
				continue
			}
			for _, c := range []struct{ what, v string }{
				{"location " + path + " redirect_url", redirectURL},
				{"location " + path + " rewrite_uri", rewriteURI},
			} {
				if c.v == "" {
					continue
				}
				if err := caddyapi.ScreenTenantTemplate(c.v); err != nil {
					hits = append(hits, inventoryHit{id, client, service, c.what + ": " + err.Error()})
				}
			}
		}
	}

	// Per-client geo-block redirect: same allow-list, client-editable field,
	// not tied to a single route id (0 = "client-level", not a route).
	crows, cerr := db.QueryContext(qCtx, `
		SELECT id, COALESCE(display_name,''), COALESCE(geo_block_redirect_url,'')
		  FROM clients WHERE COALESCE(geo_block_redirect_url,'') <> ''`)
	if cerr == nil {
		defer crows.Close()
		for crows.Next() {
			var id int64
			var name, redirectURL string
			if err := crows.Scan(&id, &name, &redirectURL); err != nil {
				continue
			}
			if err := caddyapi.ScreenTenantTemplate(redirectURL); err != nil {
				hits = append(hits, inventoryHit{0, name, "(client geo_block_redirect_url)", err.Error()})
			}
		}
	}

	return []check{summarizeHits("routes: stored placeholder allow-list", hits)}
}

// doctorStoredWAF screens every stored waf_directives blob against the same
// structural screen SanitizeWAFDirectives applies at emission time (#14 class:
// a line that screen would drop today).
func doctorStoredWAF(ctx context.Context, db *sql.DB) []check {
	qCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var hits []inventoryHit

	rows, err := db.QueryContext(qCtx, `
		SELECT r.id, COALESCE(cl.display_name,''), COALESCE(sv.name,''), COALESCE(r.waf_enabled,0), r.waf_directives
		  FROM routes r
		  JOIN services sv ON sv.id = r.service_id
		  LEFT JOIN clients cl ON cl.id = sv.client_id
		 WHERE COALESCE(r.waf_directives,'') <> ''
		 ORDER BY r.id`)
	if err != nil {
		return []check{{"routes: stored WAF directives", statusFail, "query failed: " + err.Error()}}
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var client, service string
		var enabled bool
		var directives sql.NullString
		if err := rows.Scan(&id, &client, &service, &enabled, &directives); err != nil {
			continue
		}
		if !directives.Valid || directives.String == "" {
			continue
		}
		if _, dropped := caddyapi.SanitizeWAFDirectives(directives.String); dropped {
			state := "disabled"
			if enabled {
				state = "enabled"
			}
			hits = append(hits, inventoryHit{id, client, service,
				fmt.Sprintf("stored WAF directives (waf_enabled=%s) contain line(s) today's screen would drop", state)})
		}
	}
	return []check{summarizeHits("routes: stored WAF directives", hits)}
}

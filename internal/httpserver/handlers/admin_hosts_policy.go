package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
	"github.com/host-yt/caddy-proxy-manager/internal/streamguard"
)

// revalidateStoredWAF refuses to re-activate a route whose stored SecLang the
// actor could not write today: a disable/enable cycle must not be a way to put
// legacy arbitrary directives back into the node's shared Coraza config.
func (h *AdminHandlers) revalidateStoredWAF(ctx context.Context, sess *auth.Session, id int64) error {
	var directives string
	if err := h.DB().QueryRowContext(ctx,
		"SELECT COALESCE(waf_directives,'') FROM routes WHERE id = ?", id).Scan(&directives); err != nil {
		return errors.New("WAF directives could not be read")
	}
	if strings.TrimSpace(directives) == "" {
		return nil
	}
	return caddyapi.ValidateWAFDirectives(directives, isSuperAdmin(sess))
}

// aliasCollision returns the first alias that already belongs to another route
// (as its primary domain or in that route's alias list), or "" when none clash.
// Prevents one route from shadowing another tenant's domain via aliases.
// domainCollision reports whether hostname is already served by a route of a
// DIFFERENT tenant, as primary domain or alias. Path is deliberately ignored:
// a more specific path on the same host still intercepts the incumbent's
// traffic. Same-tenant path splitting stays allowed (unique domain+path
// still applies).
func domainCollision(ctx context.Context, q rowQuerier, hostname string, routeID int64) (bool, error) {
	if q == nil || strings.TrimSpace(hostname) == "" {
		return false, nil
	}
	var hit int
	if err := q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM routes r
		   JOIN services s ON s.id = r.service_id
		  WHERE r.id <> ? AND r.status <> 'deleted'
		    AND (r.domain = ? OR FIND_IN_SET(?, r.aliases) > 0)
		    AND s.client_id <> (SELECT s2.client_id FROM routes r2
		                          JOIN services s2 ON s2.id = r2.service_id
		                         WHERE r2.id = ?)`,
		routeID, hostname, hostname, routeID).Scan(&hit); err != nil {
		return false, err
	}
	return hit > 0, nil
}

func aliasCollision(ctx context.Context, q rowQuerier, aliasCSV string, excludeRouteID int64) (string, error) {
	if q == nil || strings.TrimSpace(aliasCSV) == "" {
		return "", nil
	}
	for _, a := range strings.Split(aliasCSV, ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		var hit int
		err := q.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM routes
			 WHERE id <> ? AND status <> 'deleted'
			   AND (domain = ? OR FIND_IN_SET(?, aliases) > 0)`,
			excludeRouteID, a, a).Scan(&hit)
		if err != nil {
			return "", err
		}
		if hit > 0 {
			return a, nil
		}
	}
	return "", nil
}

// screenBackendHost SSRF-screens a single reverse-proxy backend through the
// central screener (loopback/metadata, admin API port, managed node, panel and
// control-plane addresses). It loads the deny set itself, so use
// screenBackendWith when several targets of one save are screened together.
func screenBackendHost(ctx context.Context, db *sql.DB, host string, port int) error {
	if strings.TrimSpace(host) == "" {
		return nil
	}
	infra, err := streamguard.LoadInfraTargets(ctx, db)
	if err != nil {
		return fmt.Errorf("backend screening unavailable: %w", err)
	}
	return screenBackendWith(ctx, infra, host, port, false)
}

// screenBackendWith applies the central screen to one target. tolerateUnresolved
// keeps a name the panel cannot resolve (tunnel backends resolve node-side)
// usable while every deny-set check still applies.
func screenBackendWith(ctx context.Context, infra *streamguard.InfraTargets, host string, port int, tolerateUnresolved bool) error {
	err := infra.ScreenHTTPBackend(ctx, host, port)
	if tolerateUnresolved && errors.Is(err, streamguard.ErrUnresolved) {
		return nil
	}
	return err
}

// unresolvedHint turns a panel-side resolution failure into the one action
// that actually unblocks the operator, instead of a dead end.
// canWaivePanelResolution gates the "backend is resolved on the node" switch.
// Waiving panel-side resolution means no resolved address is ever screened, so
// it stays with the unrestricted role rather than any scoped admin.
func canWaivePanelResolution(role string) bool { return role == "super_admin" }

// sessRole is the caller's role, or "" when there is no session - an absent
// session must never read as a privileged one.
func sessRole(sess *auth.Session) string {
	if sess == nil {
		return ""
	}
	return sess.Role
}

// screenSSOTarget screens what the SSO subroutes actually dial, using the same
// target definition (caddyapi.SSODialTarget) and the same screener as emission
// - one policy, two moments, so a save cannot store a route that will be held
// back at push. peerIP is the bound tunnel peer, which replaces the URL host.
func screenSSOTarget(ctx context.Context, infra *streamguard.InfraTargets, providerURL, peerIP string) error {
	if strings.TrimSpace(providerURL) == "" {
		return nil
	}
	host, port, ok := caddyapi.SSODialTarget(caddyapi.Route{
		SSOProviderURL: providerURL,
		SSOResolver:    strings.TrimSpace(peerIP),
	})
	if !ok {
		return errors.New("provider URL has no dialable host:port")
	}
	return screenBackendWith(ctx, infra, host, port, false)
}

// errResolverNeedsWaiver is the refusal for a submitted DNS resolver. The
// operator is told rather than having the value dropped: a split-horizon name
// that stops resolving is otherwise a silent outage.
var errResolverNeedsWaiver = errors.New("a custom DNS resolver for this backend requires super_admin")

// resolverForSave applies the write policy for a host save's DNS resolver
// columns (HPG-SEC-001a). A submitted resolver decides what the node dials
// without the panel ever screening the answer, so it takes the same waiver as
// node-side resolution. The tunnel auto-bind for a hostname backend is
// panel-generated, not tenant input, and is inert without that waiver - it is
// applied after the gate and needs no role.
func resolverForSave(role, ip string, peerID int64, kind, backendIP string, viaPeerID int64) (string, int64, bool, error) {
	ip = strings.TrimSpace(ip)
	if ip != "" || peerID > 0 {
		if !canWaivePanelResolution(role) {
			return "", 0, false, errResolverNeedsWaiver
		}
		if ip != "" {
			peerID = 0 // mutual exclusion: direct IP beats peer
		}
		return ip, peerID, false, nil
	}
	// Tunnel + hostname backend: keep the name and resolve it through the
	// tunnel, so dynamic upstreams query container DNS on the peer.
	if kind == "proxy" && viaPeerID > 0 && backendIP != "" && net.ParseIP(backendIP) == nil {
		return "", viaPeerID, true, nil
	}
	return "", 0, false, nil
}

func unresolvedHint(err error, fallback string) string {
	if errors.Is(err, streamguard.ErrUnresolved) {
		return "backend hostname does not resolve from the panel - fix DNS, or tick " +
			"\"backend is resolved on the node\" if only the node can resolve this name"
	}
	return fallback
}

// ssoStrictFromForm resolves the posted SSO gate against the stored one.
// A save that does not carry the field leaves the gate alone, so permissive
// mode can only ever be re-entered by an operator choosing it.
func ssoStrictFromForm(form url.Values, stored bool) bool {
	vals, ok := form["sso_strict_mode"]
	if !ok {
		return stored
	}
	return slices.Contains(vals, "1")
}

func isValidUpstreamHost(h string) bool {
	h = strings.TrimSpace(h)
	if h == "" || len(h) > 253 {
		return false
	}
	if net.ParseIP(h) != nil {
		return true
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i, c := range label {
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '-'
			if !ok || (c == '-' && (i == 0 || i == len(label)-1)) {
				return false
			}
		}
	}
	return true
}

// verificationResetRequired reports whether a matcher (domain/path) change must
// re-arm the DNS ownership proof. Only a full platform admin is trusted to name
// a domain (routes.Create lands theirs verified); everyone else must re-prove
// control, or an owned route becomes a takeover of any hostname they type.
func (h *AdminHandlers) verificationResetRequired(ctx context.Context, sess *auth.Session, matcherChanged bool) bool {
	if !matcherChanged {
		return false
	}
	tenantScoped, provOK := h.selfProvisionScope(ctx, sess)
	return !provOK || tenantScoped
}

// resolveCustomConfig returns the custom_config value that may actually be
// persisted for routeID. Both the stored and the submitted chain go through the
// allow-list: a chain written before the current policy is quarantined rather
// than carried forward. Any real change is platform-admin only, because a raw
// Caddy handler reaches the node's local admin API and every tenant on it.
func (h *AdminHandlers) resolveCustomConfig(ctx context.Context, sess *auth.Session, routeID int64, raw string) (string, error) {
	var stored sql.NullString
	if err := h.DB().QueryRowContext(ctx,
		"SELECT custom_config FROM routes WHERE id = ?", routeID).Scan(&stored); err != nil {
		return "", errors.New("lookup failed")
	}
	storedRaw := strings.TrimSpace(stored.String)
	current, cerr := sanitizeCustomConfig(storedRaw)
	if cerr != nil {
		// Legacy non-conforming chain: drop it instead of re-persisting it, and
		// do not block an unrelated edit that resubmits the prefilled value.
		current = ""
		if strings.TrimSpace(raw) == storedRaw {
			return "", nil
		}
	}
	submitted, err := sanitizeCustomConfig(raw)
	if err != nil {
		return "", err
	}
	if submitted == current {
		return current, nil
	}
	if tenantScoped, provOK := h.selfProvisionScope(ctx, sess); !provOK || tenantScoped {
		return "", errors.New("custom Caddy handlers are platform-admin only")
	}
	return submitted, nil
}

// checkWAFDirectives is the write-time gate for custom SecLang. One node
// compiles every tenant's directives into a single Coraza config, so arbitrary
// directives are node-operator power: super_admin only. Resubmitting the
// stored value unchanged is allowed so a legacy row cannot lock a lesser admin
// out of every other field; the enable path re-checks it before re-publishing.
func (h *AdminHandlers) checkWAFDirectives(ctx context.Context, sess *auth.Session, routeID int64, raw string) error {
	if err := caddyapi.ValidateWAFDirectives(raw, true); err != nil {
		return err // structural: not storable by anyone
	}
	if isSuperAdmin(sess) {
		return nil
	}
	if err := caddyapi.ValidateWAFDirectives(raw, false); err == nil {
		return nil
	}
	var stored sql.NullString
	if qerr := h.DB().QueryRowContext(ctx,
		"SELECT waf_directives FROM routes WHERE id = ?", routeID).Scan(&stored); qerr != nil {
		return errors.New("lookup failed")
	}
	if strings.TrimSpace(stored.String) == strings.TrimSpace(raw) {
		return nil
	}
	return caddyapi.ValidateWAFDirectives(raw, false)
}

// sanitizeCustomConfig is the write-side entry point for the shared Caddy
// handler allow-list; caddyapi re-runs it at emission time.
func sanitizeCustomConfig(raw string) (string, error) {
	return caddyapi.SanitizeCustomHandlers(raw)
}

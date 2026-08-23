// Route lifecycle: create, ownership proof, delete, and the state machine
// that walks a new route to 'active'.
package routes

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/host-yt/caddy-proxy-manager/internal/dns"
	"github.com/host-yt/caddy-proxy-manager/internal/quota"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// Create inserts a route, picks a node, runs DNS pre-check synchronously
// (best-effort), and pushes the node config to Caddy. Returns the new
// route id.
func (s *Service) Create(ctx context.Context, clientID int64, in CreateInput) (int64, error) {
	domain := strings.ToLower(strings.TrimSpace(in.Domain))
	pathPrefix := strings.TrimSpace(in.PathPrefix)
	if domain == "" || !validDomain(domain) {
		return 0, ErrInvalidDomain
	}
	if pathPrefix != "" {
		if !strings.HasPrefix(pathPrefix, "/") {
			pathPrefix = "/" + pathPrefix
		}
		if strings.Contains(pathPrefix, "..") {
			return 0, ErrInvalidDomain
		}
	}

	// Verify service ownership + read port range + node_group + plan.
	var (
		backendIP    string
		portStart    int
		portEnd      int
		ownerClient  int64
		nodeGroupID  int64
		planSSL      bool
		planWS       bool
		planPath     bool
		planMaxDom   int
		planWild     bool
		planExtProxy bool
	)
	err := s.DB.QueryRowContext(ctx,
		`SELECT s.client_id, s.backend_ip, s.allowed_port_start, s.allowed_port_end, s.node_group_id,
		        p.ssl_enabled, p.websocket_enabled, p.path_routing_enabled, p.max_domains, p.wildcard_enabled,
		        p.external_proxy_enabled
		 FROM services s JOIN plans p ON p.id = s.plan_id
		 WHERE s.id = ? LIMIT 1`,
		in.ServiceID,
	).Scan(&ownerClient, &backendIP, &portStart, &portEnd, &nodeGroupID, &planSSL, &planWS, &planPath, &planMaxDom, &planWild, &planExtProxy)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrServiceNotYours
	}
	if err != nil {
		return 0, fmt.Errorf("service lookup: %w", err)
	}
	// 0 clientID means "called from admin/API context" - allow.
	if clientID != 0 && ownerClient != clientID {
		return 0, ErrServiceNotYours
	}
	// External-HTTPS-upstream setup (admin-only). Validate the FQDN against
	// the allowlist (primary open-relay defense) and force the route shape:
	// https proxy to the origin's :443, its own cert via On-Demand TLS.
	var externalHost, encSecret string
	if in.External {
		// Per-plan gate. Admin/API context (clientID==0) still requires the
		// plan flag; the admin-self plan is kind='npm' which the migration
		// sets external_proxy_enabled=1, so super_admin works out of the box.
		if !planExtProxy {
			return 0, ErrExternalNotInPlan
		}
		externalHost = strings.ToLower(strings.TrimSpace(in.ExternalHost))
		if !s.externalHostAllowed(externalHost) {
			return 0, ErrExternalHostNotAllowed
		}
		in.Kind = "proxy"
		in.UpstreamScheme = "https"
		in.SSL = true
		if in.UpstreamPort == 0 {
			in.UpstreamPort = 443
		}
		if in.ProxySecretPlain != "" {
			if s.EncryptSecret == nil {
				return 0, fmt.Errorf("external route secret encryption not configured")
			}
			encSecret, err = s.EncryptSecret(in.ProxySecretPlain)
			if err != nil {
				return 0, fmt.Errorf("encrypt proxy secret: %w", err)
			}
		}
	}

	// Redirect routes have no upstream; skip the port-range check and
	// store port=0 so the column (NOT NULL) stays valid. External routes
	// target the origin's port (443), not the customer range, so skip too.
	if in.Kind == "redirect" {
		in.UpstreamPort = 0
		if in.RedirectURL == "" {
			return 0, fmt.Errorf("redirect_url is required for redirect routes")
		}
		switch in.RedirectCode {
		case 0:
			in.RedirectCode = 308
		case 301, 302, 307, 308:
		default:
			return 0, fmt.Errorf("redirect_code must be 301/302/307/308")
		}
	} else if !in.External && (in.UpstreamPort < portStart || in.UpstreamPort > portEnd) {
		return 0, ErrPortOutOfRange
	}
	// Reject a backend port already claimed by another route in this service's pool.
	if in.Kind != "redirect" && !in.External {
		var portUsed int
		if err := s.DB.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM routes WHERE service_id = ? AND upstream_port = ?",
			in.ServiceID, in.UpstreamPort,
		).Scan(&portUsed); err == nil && portUsed > 0 {
			return 0, ErrPortInUse
		}
	}
	if pathPrefix != "" && !planPath {
		return 0, fmt.Errorf("plan does not permit path routing")
	}
	// Plan limit: max_domains counted across this service.
	if planMaxDom > 0 {
		var currentCount int
		if err := s.DB.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM routes WHERE service_id = ?", in.ServiceID,
		).Scan(&currentCount); err == nil && currentCount >= planMaxDom {
			return 0, ErrMaxDomains
		}
	}
	// Reseller aggregate quota. Single choke point: panel, client portal and
	// API route creation all pass through here. Lookup errors log + allow
	// (business limit, must not brick creates on a transient).
	if s.Quota != nil {
		rid, qerr := s.Quota.ResellerOfClient(ctx, ownerClient)
		if qerr == nil && rid != 0 {
			qerr = s.Quota.CanCreateRoute(ctx, rid, in.ServiceID)
		}
		if errors.Is(qerr, quota.ErrDomainQuota) {
			return 0, qerr
		}
		if qerr != nil {
			s.Logger.Warn("reseller quota check skipped", "client", ownerClient, "err", qerr)
		}
	}

	// Plan flags constrain customer choice. External routes always need their
	// own cert (the node domain), so the plan SSL flag can't disable them.
	if !planSSL && !in.External {
		in.SSL = false
	}
	if !planWS {
		in.WebSocket = false
	}

	// Wildcard DNS-01: plan-gated for customers (admin clientID==0 bypasses,
	// like External). Require an enabled dns_providers row for the zone (else
	// the cert can never issue) and that the domain is the zone or a subdomain
	// of it (else *.zone would not cover it). DNS A/AAAA is still required for
	// the host data-plane and is checked later in advanceRoute.
	var wildcardZone string
	if in.WildcardEnabled {
		if clientID != 0 && !planWild {
			return 0, fmt.Errorf("plan does not permit wildcard certificates")
		}
		wildcardZone = strings.ToLower(strings.TrimSpace(in.WildcardZone))
		if wildcardZone == "" || !validDomain(wildcardZone) {
			return 0, ErrWildcardZoneMismatch
		}
		if domain != wildcardZone && !strings.HasSuffix(domain, "."+wildcardZone) {
			return 0, ErrWildcardZoneMismatch
		}
		var n int
		if err := s.DB.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM dns_providers WHERE name = ?", wildcardZone).Scan(&n); err != nil || n == 0 {
			return 0, ErrWildcardNoProvider
		}
	}

	// Pick node(s) based on group mode: single / active_active / failover.
	// Primary slot lands in routes.caddy_node_id; for fan-out modes the
	// other nodes get rows in route_node_assignments after insert.
	var (
		primaryNode int64
		allNodes    []int64
		groupMode   string
	)
	primaryNode, allNodes, groupMode, err = nodePlacement(ctx, s.DB, nodeGroupID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrNoNodeFound
		}
		return 0, fmt.Errorf("node placement: %w", err)
	}
	nodeID := primaryNode

	// Tunnel guard: peer must belong to the owning client and cover the
	// placed node (directly or via its peer group), else Caddy would dial
	// through a nonexistent wg interface. Returns peer IP for the override
	// dedupe below.
	var tunnelPeerIP string
	if in.ViaWGPeerID > 0 {
		if err := s.DB.QueryRowContext(ctx,
			`SELECT COALESCE(p_base.assigned_ip,'') FROM customer_wg_peer p_base
			  WHERE p_base.id = ? AND p_base.client_id = ? AND p_base.status <> 'revoked'
			    AND EXISTS (SELECT 1 FROM customer_wg_peer p_use
			                 WHERE p_use.status <> 'revoked' AND p_use.node_id = ?
			                   AND (p_use.id = p_base.id OR
			                        (p_base.peer_group_id IS NOT NULL AND p_use.peer_group_id = p_base.peer_group_id)))`,
			in.ViaWGPeerID, ownerClient, nodeID).Scan(&tunnelPeerIP); err != nil {
			return 0, ErrTunnelNotOnNode
		}
	}

	// Insert + increment counter in a transaction.
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck

	kind := in.Kind
	if kind != "redirect" {
		kind = "proxy"
	}
	var redirURL sql.NullString
	if in.RedirectURL != "" {
		redirURL = sql.NullString{String: in.RedirectURL, Valid: true}
	}
	var redirCode sql.NullInt32
	if in.RedirectCode != 0 {
		redirCode = sql.NullInt32{Int32: int32(in.RedirectCode), Valid: true}
	}
	var tagVal sql.NullString
	if t := strings.TrimSpace(in.Tag); t != "" {
		if len(t) > 64 {
			t = t[:64]
		}
		tagVal = sql.NullString{String: t, Valid: true}
	}
	scheme := in.UpstreamScheme
	if scheme != "https" {
		scheme = "http"
	}
	// External-route columns (NULL/0 for normal routes).
	var backendOverride, hostHeader, secretEnc sql.NullString
	extFlag := 0
	// Tunnel route: per-route override beats peer IP in the build COALESCE;
	// hostname backends also get the peer as DNS resolver (dynamic upstreams).
	// No override when backend equals peer IP - fan-out nodes must pick their
	// own group member's IP.
	var viaPeer, dnsResolverPeer sql.NullInt64
	if in.ViaWGPeerID > 0 && kind == "proxy" && !in.External {
		viaPeer = sql.NullInt64{Int64: in.ViaWGPeerID, Valid: true}
		if backendIP != "" && backendIP != tunnelPeerIP {
			backendOverride = sql.NullString{String: backendIP, Valid: true}
			if !looksLikeIP(backendIP) {
				dnsResolverPeer = viaPeer
			}
		}
	}
	if in.External {
		extFlag = 1
		backendOverride = sql.NullString{String: externalHost, Valid: true}
		hh := strings.TrimSpace(in.UpstreamHostHeader)
		if hh == "" {
			hh = externalHost
		}
		hostHeader = sql.NullString{String: hh, Valid: true}
		if encSecret != "" {
			secretEnc = sql.NullString{String: encSecret, Valid: true}
		}
	}
	// Wildcard columns (0/NULL for normal routes).
	var wildFlag int
	var wildZone sql.NullString
	if in.WildcardEnabled {
		wildFlag = 1
		wildZone = sql.NullString{String: wildcardZone, Valid: true}
	}
	// Domain-ownership gate: admin/API context (clientID==0) is trusted and lands
	// verified; self-service routes land unverified with a token the owner must
	// publish as a DNS TXT record before the route can advance or get a cert.
	verified := 0
	verifyToken := ""
	if clientID == 0 {
		verified = 1
	} else {
		verifyToken, err = newVerifyToken()
		if err != nil {
			return 0, fmt.Errorf("verify token: %w", err)
		}
	}
	// Anti-squat: the UNIQUE(domain,path) constraint would otherwise let a
	// squatter's first-come UNVERIFIED row permanently block a later claim for the
	// same domain. If the sole conflicting row is unverified, evict it inside this
	// tx so the new claim can proceed (both then race to prove ownership via TXT).
	// A VERIFIED conflicting row is never displaced - that owner proved control.
	var conflictID, conflictVerified int64
	var conflictNode sql.NullInt64
	if e := tx.QueryRowContext(ctx,
		`SELECT id, domain_verified, caddy_node_id FROM routes
		 WHERE domain = ? AND COALESCE(path_prefix,'') = ? LIMIT 1`,
		domain, pathPrefix,
	).Scan(&conflictID, &conflictVerified, &conflictNode); e == nil {
		if conflictVerified == 1 {
			return 0, ErrDomainTaken
		}
		if _, e := tx.ExecContext(ctx, "DELETE FROM routes WHERE id = ? AND domain_verified = 0", conflictID); e != nil {
			return 0, ErrDomainTaken
		}
		if conflictNode.Valid && conflictNode.Int64 != 0 {
			_, _ = tx.ExecContext(ctx,
				"UPDATE caddy_nodes SET current_routes = GREATEST(current_routes - 1, 0) WHERE id = ?", conflictNode.Int64)
		}
		s.Logger.Warn("anti-squat: evicted unverified route on create", "evicted_id", conflictID, "domain", domain)
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO routes (service_id, caddy_node_id, domain, path_prefix, upstream_port, upstream_scheme,
		   ssl_enabled, websocket, force_https, http2_enabled, http3_enabled, status,
		   kind, redirect_url, redirect_code, tag,
		   backend_ip_override, upstream_external, upstream_host_header, proxy_secret_enc,
		   wildcard_enabled, wildcard_zone, group_id, custom_fields,
		   via_wg_peer_id, dns_resolver_via_wg_peer_id,
		   domain_verified, verify_token)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, 'pending_dns', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULLIF(?, 0), NULLIF(?, ''), ?, ?, ?, ?)`,
		in.ServiceID, nodeID, domain, pathPrefix, in.UpstreamPort, scheme,
		in.SSL, in.WebSocket, in.ForceHTTPS,
		kind, redirURL, redirCode, tagVal,
		backendOverride, extFlag, hostHeader, secretEnc,
		wildFlag, wildZone, in.GroupID, in.CustomFields,
		viaPeer, dnsResolverPeer,
		verified, verifyToken)
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") {
			return 0, ErrDomainTaken
		}
		return 0, fmt.Errorf("route insert: %w", err)
	}
	routeID, _ := res.LastInsertId()
	// Claim the slot conditionally, in the same transaction as the insert.
	// Placement read current_routes < max_routes outside any lock, so two
	// concurrent creates could both see the same last free slot and both bump
	// the counter past max_routes. The WHERE clause makes the claim atomic:
	// exactly one of them updates a row, the other is told to retry.
	claim, err := tx.ExecContext(ctx,
		"UPDATE caddy_nodes SET current_routes = current_routes + 1 WHERE id = ? AND current_routes < max_routes",
		nodeID)
	if err != nil {
		return 0, fmt.Errorf("node counter bump: %w", err)
	}
	if n, _ := claim.RowsAffected(); n == 0 {
		// Single-mode placement can simply move to another node with room.
		// Not attempted for a tunnel route (the peer was validated against the
		// originally placed node) or for fan-out modes (the peer set was chosen
		// as a whole), where the caller retries instead.
		alt, ok := int64(0), false
		if groupMode == "single" && in.ViaWGPeerID == 0 {
			alt, ok = claimNodeWithCapacity(ctx, tx, nodeGroupID, nodeID)
		}
		if !ok {
			return 0, ErrNodeAtCapacity
		}
		if _, err := tx.ExecContext(ctx,
			"UPDATE routes SET caddy_node_id = ? WHERE id = ?", alt, routeID); err != nil {
			return 0, fmt.Errorf("re-place route: %w", err)
		}
		s.Logger.Warn("primary node filled up between placement and claim; re-placed",
			"route_id", routeID, "domain", domain, "from_node", nodeID, "to_node", alt)
		nodeID = alt
		allNodes = []int64{alt}
	}
	// Fan-out modes: record every target node in the assignments join table.
	// active_active deploys to all peers; failover deploys to primary + one
	// warm standby so the standby has the route ready when it's promoted.
	// assignedNodes is the set whose slots we actually hold, which is what the
	// post-commit pushes must target: a peer skipped for capacity has no
	// assignment row, so pushing to it would be a no-op round trip.
	assignedNodes := []int64{nodeID}
	if groupMode != "single" && len(allNodes) > 1 {
		for _, n := range allNodes {
			if n != nodeID {
				// Same atomic claim as the primary. A peer that filled up since
				// placement is skipped rather than oversubscribed: the route
				// still lands on the peers that had room, and the assignment is
				// only recorded for nodes whose slot we actually hold.
				peerClaim, err := tx.ExecContext(ctx,
					"UPDATE caddy_nodes SET current_routes = current_routes + 1 WHERE id = ? AND current_routes < max_routes",
					n)
				if err != nil {
					return 0, fmt.Errorf("peer counter bump: %w", err)
				}
				if got, _ := peerClaim.RowsAffected(); got == 0 {
					s.Logger.Warn("fan-out peer at capacity, skipped",
						"route_id", routeID, "node_id", n, "domain", domain)
					continue
				}
			}
			if _, err := tx.ExecContext(ctx,
				store.InsertOrIgnore()+" INTO route_node_assignments (route_id, node_id) VALUES (?, ?)",
				routeID, n); err != nil {
				return 0, fmt.Errorf("fan-out assign: %w", err)
			}
			if n != nodeID {
				assignedNodes = append(assignedNodes, n)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}

	// Best-effort lifecycle. Failures are recorded in the row, not returned.
	// Bound it: advanceRoute does a DNS lookup + Caddy push and must not pile
	// up holding a DB connection unbounded under burst route creation.
	go func() {
		defer recoverBg(s.Logger, "advanceRoute")
		ctx, cancel := context.WithTimeout(s.BackgroundCtx(), 45*time.Second)
		defer cancel()
		s.advanceRoute(ctx, routeID)
	}()
	if groupMode != "single" {
		for _, n := range assignedNodes {
			if n == nodeID {
				continue // the anchor is pushed by advanceRoute
			}
			s.schedulePush(n)
		}
	}
	return routeID, nil
}

// VerifyDNS re-runs the DNS check for an existing route and re-pushes
// to Caddy if it transitions to dns_ok.
func (s *Service) VerifyDNS(ctx context.Context, clientID, routeID int64) error {
	var ownerClient int64
	if err := s.DB.QueryRowContext(ctx,
		`SELECT sv.client_id FROM routes r JOIN services sv ON sv.id = r.service_id WHERE r.id = ?`,
		routeID,
	).Scan(&ownerClient); err != nil {
		return err
	}
	if clientID != 0 && ownerClient != clientID {
		return ErrServiceNotYours
	}
	s.advanceRoute(ctx, routeID)
	return nil
}

// ErrAlreadyVerified: the route's domain is already proven; nothing to do.
var ErrAlreadyVerified = errors.New("domain already verified")

// ErrVerifyTokenMissing: TXT record at _hpg-verify.<domain> did not contain the
// route's token (owner hasn't published it yet, or it's wrong).
var ErrVerifyTokenMissing = errors.New("verification TXT record not found")

// VerifyDomainToken proves the caller controls the route's domain by looking up
// a DNS TXT record at _hpg-verify.<domain> and matching it against the route's
// verify_token. On success it marks the route verified, evicts any STALE
// UNVERIFIED squatter routes on the same domain+path owned by a different tenant
// (anti-squat takeover), then advances the route. Returns the token+FQDN so the
// caller can re-surface instructions on failure.
func (s *Service) VerifyDomainToken(ctx context.Context, clientID, routeID int64) (token, recordName string, err error) {
	var (
		ownerClient int64
		domain      string
		pathPrefix  sql.NullString
		verified    int
		tok         sql.NullString
		aliases     sql.NullString
	)
	if err = s.DB.QueryRowContext(ctx,
		`SELECT sv.client_id, r.domain, r.path_prefix, r.domain_verified, r.verify_token,
		        COALESCE(r.aliases,'')
		 FROM routes r JOIN services sv ON sv.id = r.service_id WHERE r.id = ?`,
		routeID,
	).Scan(&ownerClient, &domain, &pathPrefix, &verified, &tok, &aliases); err != nil {
		return "", "", err
	}
	if clientID != 0 && ownerClient != clientID {
		return "", "", ErrServiceNotYours
	}
	token = tok.String
	recordName = "_hpg-verify." + domain
	// Aliases are proven independently of the primary domain, so sweep them on
	// every attempt - including one on an already-verified route.
	s.verifyAliases(ctx, routeID, aliases.String, token)
	if verified == 1 {
		return token, recordName, ErrAlreadyVerified
	}
	if token == "" {
		// No token on the row (shouldn't happen for self-service creates); refuse
		// rather than silently verifying.
		return token, recordName, ErrVerifyTokenMissing
	}
	if !dns.TXTContains(ctx, recordName, token) {
		return token, recordName, ErrVerifyTokenMissing
	}

	// Anti-squat takeover: now that this tenant PROVED ownership, remove any
	// still-unverified route rows for the same domain+path held by a DIFFERENT
	// tenant so their stale first-come claim can't keep blocking the real owner.
	// Only unverified rows are evicted - a verified conflicting claim is left
	// intact (that owner also proved control; a genuine dispute is out of scope).
	rows, derr := s.DB.QueryContext(ctx,
		`SELECT id, caddy_node_id FROM routes
		 WHERE domain = ? AND COALESCE(path_prefix,'') = COALESCE(?, '')
		   AND id <> ? AND domain_verified = 0`,
		domain, pathPrefix, routeID)
	if derr == nil {
		type stale struct{ id, node int64 }
		var stales []stale
		for rows.Next() {
			var st stale
			var node sql.NullInt64
			if rows.Scan(&st.id, &node) == nil {
				st.node = node.Int64
				stales = append(stales, st)
			}
		}
		rows.Close()
		for _, st := range stales {
			if _, e := s.DB.ExecContext(ctx, "DELETE FROM routes WHERE id = ? AND domain_verified = 0", st.id); e == nil {
				s.Logger.Warn("anti-squat: evicted unverified route", "evicted_id", st.id, "domain", domain, "winner_id", routeID)
				if st.node != 0 {
					_, _ = s.DB.ExecContext(ctx,
						"UPDATE caddy_nodes SET current_routes = GREATEST(current_routes - 1, 0) WHERE id = ?", st.node)
					// Row already gone: drop it from the squatter's node config.
					nodeID := st.node
					evID := st.id
					go func() {
						defer recoverBg(s.Logger, "antiSquat.removeRoute")
						c, cancel := context.WithTimeout(s.BackgroundCtx(), 30*time.Second)
						defer cancel()
						_ = s.pushRouteIncremental(c, nodeID, evID, routeRemove)
					}()
				}
			}
		}
	}

	if _, err = s.DB.ExecContext(ctx,
		"UPDATE routes SET domain_verified = 1, last_error = NULL, updated_at = NOW() WHERE id = ?",
		routeID); err != nil {
		return token, recordName, err
	}
	s.advanceRoute(ctx, routeID)
	return token, recordName, nil
}

// verifyAliases proves each alias with the same TXT nonce at _hpg-verify.<alias>
// and records the proven subset in routes.aliases_verified. An alias that is not
// proven is never emitted as a host matcher and never gets a certificate, so an
// operator cannot bolt a victim hostname onto a route they already own.
// Returns the proven subset after the sweep.
func (s *Service) verifyAliases(ctx context.Context, routeID int64, aliases, token string) []string {
	list := splitHostList(aliases)
	if token == "" || len(list) == 0 {
		return nil
	}
	var prev sql.NullString
	if err := s.DB.QueryRowContext(ctx,
		"SELECT COALESCE(aliases_verified,'') FROM routes WHERE id = ?", routeID).Scan(&prev); err != nil {
		return nil
	}
	proven := map[string]bool{}
	for _, a := range splitHostList(prev.String) {
		proven[a] = true
	}
	out := []string{}
	changed := false
	for _, a := range list {
		if !proven[a] {
			if !dns.TXTContains(ctx, "_hpg-verify."+a, token) {
				continue
			}
			changed = true
		}
		out = append(out, a)
	}
	// Also collapses a stale entry for a removed alias.
	joined := strings.Join(out, ",")
	if !changed && joined == strings.Join(splitHostList(prev.String), ",") {
		return out
	}
	if _, err := s.DB.ExecContext(ctx,
		"UPDATE routes SET aliases_verified = ? WHERE id = ?", joined, routeID); err != nil {
		s.Logger.Warn("alias verification: persist", "route_id", routeID, "err", err)
		return splitHostList(prev.String)
	}
	var nodeID sql.NullInt64
	if err := s.DB.QueryRowContext(ctx,
		"SELECT caddy_node_id FROM routes WHERE id = ?", routeID).Scan(&nodeID); err == nil && nodeID.Int64 > 0 {
		s.SchedulePush(nodeID.Int64)
	}
	return out
}

// RecheckPendingAliases re-runs the TXT proof for every route that still has
// unproven aliases. Migration 00138 dropped the 00136 backfill, so an owner
// whose _hpg-verify record is already published recovers here with no manual
// step; a legacy claim that fully re-proves is closed out automatically.
func (s *Service) RecheckPendingAliases(ctx context.Context) {
	if s.DB == nil {
		return
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, COALESCE(aliases,''), COALESCE(aliases_verified,''), COALESCE(verify_token,'')
		   FROM routes
		  WHERE aliases IS NOT NULL AND aliases <> '' AND status <> 'disabled'
		  ORDER BY id ASC LIMIT 500`)
	if err != nil {
		s.Logger.Warn("alias recheck: list", "err", err)
		return
	}
	type pending struct {
		id             int64
		aliases, token string
	}
	var todo []pending
	for rows.Next() {
		var p pending
		var verified string
		if rows.Scan(&p.id, &p.aliases, &verified, &p.token) != nil {
			continue
		}
		if p.token == "" || len(unprovenHosts(p.aliases, verified)) == 0 {
			continue
		}
		todo = append(todo, p)
	}
	rows.Close()
	for _, p := range todo {
		if ctx.Err() != nil {
			return
		}
		proven := s.verifyAliases(ctx, p.id, p.aliases, p.token)
		if len(unprovenHosts(p.aliases, strings.Join(proven, ","))) > 0 {
			continue
		}
		_, _ = s.DB.ExecContext(ctx,
			`UPDATE route_alias_legacy_claims SET status='proven', resolved_at=NOW()
			  WHERE route_id = ? AND status = 'pending'`, p.id)
	}
}

// unprovenHosts returns the entries of aliases that are absent from verified.
func unprovenHosts(aliases, verified string) []string {
	ok := map[string]bool{}
	for _, v := range splitHostList(verified) {
		ok[v] = true
	}
	out := []string{}
	for _, a := range splitHostList(aliases) {
		if !ok[a] {
			out = append(out, a)
		}
	}
	return out
}

// Delete removes the route, decrements the node counter, and rebuilds the
// node config so Caddy stops serving the domain.
func (s *Service) Delete(ctx context.Context, clientID, routeID int64) error {
	var ownerClient, nodeID int64
	if err := s.DB.QueryRowContext(ctx,
		`SELECT sv.client_id, r.caddy_node_id FROM routes r
		 JOIN services sv ON sv.id = r.service_id WHERE r.id = ?`,
		routeID,
	).Scan(&ownerClient, &nodeID); err != nil {
		return err
	}
	if clientID != 0 && ownerClient != clientID {
		return ErrServiceNotYours
	}

	// Collect all fan-out nodes before the transaction so we can decrement
	// every node that holds a copy of this route.
	fanOutNodes, err := s.fanOutNodes(ctx, routeID, nodeID)
	if err != nil {
		return err
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, "DELETE FROM routes WHERE id = ?", routeID); err != nil {
		return err
	}
	// Decrement primary node.
	if _, err := tx.ExecContext(ctx,
		"UPDATE caddy_nodes SET current_routes = GREATEST(current_routes - 1, 0) WHERE id = ?", nodeID); err != nil {
		return err
	}
	// Decrement fan-out peers and clean up assignments table.
	if len(fanOutNodes) > 0 {
		for _, peerID := range fanOutNodes {
			if _, err := tx.ExecContext(ctx,
				"UPDATE caddy_nodes SET current_routes = GREATEST(current_routes - 1, 0) WHERE id = ?", peerID); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx,
			"DELETE FROM route_node_assignments WHERE route_id = ?", routeID); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	allNodes := append([]int64{nodeID}, fanOutNodes...)
	go func() {
		defer recoverBg(s.Logger, "pushRouteIncremental.remove")
		ctx, cancel := context.WithTimeout(s.BackgroundCtx(), 30*time.Second)
		defer cancel()
		// Row is already deleted: remove the route from every node it was on.
		for _, nid := range allNodes {
			_ = s.pushRouteIncremental(ctx, nid, routeID, routeRemove)
		}
	}()
	return nil
}

// fanOutNodes returns node IDs in route_node_assignments for routeID,
// excluding the primary node (already tracked via caddy_node_id).
func (s *Service) fanOutNodes(ctx context.Context, routeID, primaryNodeID int64) ([]int64, error) {
	rows, err := s.DB.QueryContext(ctx,
		"SELECT node_id FROM route_node_assignments WHERE route_id = ? AND node_id != ?",
		routeID, primaryNodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// advanceRoute: DNS check → status update → push if eligible.
func (s *Service) advanceRoute(ctx context.Context, routeID int64) {
	var (
		nodeID       int64
		domain       string
		nodeHostname sql.NullString
		nodeIP       sql.NullString
		verified     int
	)
	if err := s.DB.QueryRowContext(ctx,
		`SELECT r.caddy_node_id, r.domain, n.public_hostname, n.public_ip, r.domain_verified
		 FROM routes r JOIN caddy_nodes n ON n.id = r.caddy_node_id WHERE r.id = ?`,
		routeID,
	).Scan(&nodeID, &domain, &nodeHostname, &nodeIP, &verified); err != nil {
		s.Logger.Error("advance: route lookup", "id", routeID, "err", err)
		return
	}

	// Domain-ownership gate: an unverified route must not advance past pending_dns
	// (no serving, no cert). Pin it to pending_dns so Reconcile keeps retrying and
	// the owner sees the "verify domain" state until the TXT proof clears it.
	if verified == 0 {
		_, _ = s.DB.ExecContext(ctx,
			"UPDATE routes SET status='pending_dns', last_error='domain ownership not verified', updated_at=NOW() WHERE id=?",
			routeID)
		s.Logger.Info("route: domain unverified, holding", "id", routeID, "domain", domain)
		return
	}

	if err := dns.Check(ctx, domain, nodeHostname.String, nodeIP.String); err != nil {
		_, _ = s.DB.ExecContext(ctx,
			"UPDATE routes SET status='pending_dns', last_error=?, dns_checked_at=NOW(), updated_at=NOW() WHERE id=?",
			truncErr(err), routeID)
		s.Logger.Info("route: dns pending", "id", routeID, "domain", domain, "err", err)
		// Push anyway: Caddy serves HTTP-01 challenge on :80 once DNS catches up.
		// For initial MVP we wait for DNS to be correct before pushing.
		return
	}
	_, _ = s.DB.ExecContext(ctx,
		"UPDATE routes SET status='dns_ok', last_error=NULL, dns_checked_at=NOW(), updated_at=NOW() WHERE id=?", routeID)

	// Incremental single-route push (covers Create-primary, VerifyDNS, Reconcile,
	// which all funnel through advanceRoute); falls back to full /load on error.
	if err := s.pushRouteIncremental(ctx, nodeID, routeID, routeUpsert); err != nil {
		_, _ = s.DB.ExecContext(ctx,
			"UPDATE routes SET status='failed', last_error=? WHERE id=?", truncErr(err), routeID)
		if s.Webhooks != nil {
			s.Webhooks.Emit(ctx, "route.failed", map[string]any{
				"route_id": routeID, "domain": domain, "node_id": nodeID,
				"error": truncErr(err),
			})
		}
		return
	}
	// On first activation set ssl_issued_at; on subsequent activations
	// (renewal) refresh it so the certs page shows recent activity.
	_, _ = s.DB.ExecContext(ctx,
		`UPDATE routes
		   SET status='active', last_error=NULL,
		       ssl_issued_at = CASE WHEN ssl_enabled = 1 THEN NOW() ELSE ssl_issued_at END
		 WHERE id=?`, routeID)
	// Fan-out peers (active_active/failover) got routes:0 at create time while
	// the route was still pending; re-push them now that it is active.
	if peers, perr := s.fanOutNodes(ctx, routeID, nodeID); perr == nil {
		for _, pid := range peers {
			s.schedulePush(pid)
		}
	}
	if s.Webhooks != nil {
		s.Webhooks.Emit(ctx, "route.active", map[string]any{
			"route_id": routeID, "domain": domain, "node_id": nodeID,
		})
	}
}

// Reconcile picks up routes stuck in non-terminal states beyond a grace
// window and re-runs advanceRoute on them. Idempotent - if the route is
// already healthy it's a no-op. Called on a slow ticker (60s).
func (s *Service) Reconcile(ctx context.Context) {
	if s.DB == nil {
		return
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id FROM routes
		 WHERE status IN ('pending_dns','dns_ok','pending_ssl','failed')
		   AND updated_at < `+store.DateSub(1, "MINUTE")+`
		 ORDER BY updated_at ASC LIMIT 100`)
	if err != nil {
		s.Logger.Warn("reconcile: list stuck routes", "err", err)
		return
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	if len(ids) == 0 {
		return
	}
	s.Logger.Info("reconcile: retry stuck routes", "n", len(ids))
	// Bounded concurrency: advanceRoute does a DNS check + push per route;
	// running 4 at once is safe because pushRouteIncremental/pushNodeConfig take
	// the per-node lock (same-node ops serialize, cross-node parallelize).
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(reconcileWorkers)
	for _, id := range ids {
		id := id
		g.Go(func() error {
			if gctx.Err() != nil {
				return nil
			}
			s.advanceRoute(gctx, id)
			return nil
		})
	}
	_ = g.Wait()
}

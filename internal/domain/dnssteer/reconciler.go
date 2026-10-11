package dnssteer

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
)

// routeLimit bounds one reconcile pass so a large fleet can't starve the
// leader's tick budget; Reconciler.cursor resumes the remainder next tick.
var routeLimit = 500

// perRouteTimeout bounds every provider call for a single route so one
// slow/unreachable DNS API can't stall the whole reconcile loop.
const perRouteTimeout = 10 * time.Second

// Reconciler keeps provider A/AAAA records in sync with node health for
// every dns_steering_enabled route. Wired onto a leader-only ticker (see
// cmd/server/main.go). DB is a lazy accessor (same pattern as jobs.*Job)
// because the pool may not be ready yet when the Reconciler is constructed.
type Reconciler struct {
	DB     func() *sql.DB
	Logger *slog.Logger
	// DecryptSecret decrypts dns_providers.api_token_enc - the same helper
	// the route config builder uses for wildcard DNS-01 credentials
	// (installstate.Manager.Decrypt; auto-detects legacy vs v2 envelopes).
	DecryptSecret func(string) (string, error)
	// NewProvider builds a Provider for (slug, decrypted fields); overridable
	// in tests to inject a fake. Defaults to the package-level NewProvider.
	NewProvider func(slug string, fields map[string]string) (Provider, error)

	// cursor is the last route id processed; in-memory is enough since a
	// leader change just restarts the rotation from the lowest id.
	cursor int64
}

func (rc *Reconciler) newProvider(slug string, fields map[string]string) (Provider, error) {
	if rc.NewProvider != nil {
		return rc.NewProvider(slug, fields)
	}
	return NewProvider(slug, fields)
}

func (rc *Reconciler) dbOrNil() *sql.DB {
	if rc.DB == nil {
		return nil
	}
	return rc.DB()
}

func (rc *Reconciler) logger() *slog.Logger {
	if rc.Logger == nil {
		return slog.Default()
	}
	return rc.Logger
}

// steeredRoute is one row from the routes SELECT below.
type steeredRoute struct {
	id            int64
	domain        string
	anchorNodeID  int64
	dnsProviderID int64
	ttlSeconds    int
}

// nodeCandidate is a node eligible to host route.domain (anchor or fan-out peer).
type nodeCandidate struct {
	id      int64
	ip      string
	enabled bool
	healthy bool
}

// Reconcile runs one pass over every steering-enabled route. A failure on a
// single route or record is persisted to dns_steering_state.last_error and
// the loop moves on - one bad credential must never block the rest of the
// fleet's DNS from healing.
func (rc *Reconciler) Reconcile(ctx context.Context) {
	db := rc.dbOrNil()
	if db == nil {
		return
	}
	// Orphans first, so an IP that moved to another node is freed before re-add.
	rc.cleanupOrphans(ctx, db)
	rows, err := db.QueryContext(ctx,
		`SELECT id, domain, caddy_node_id, dns_provider_id, dns_steering_ttl
		   FROM routes
		  WHERE dns_steering_enabled = 1
		    AND domain_verified = 1
		    AND dns_provider_id IS NOT NULL
		    AND status <> 'disabled'
		    AND id > ?
		  ORDER BY id ASC LIMIT ?`, rc.cursor, routeLimit)
	if err != nil {
		rc.logger().Warn("dnssteer: list routes", "err", err)
		return
	}
	var targets []steeredRoute
	for rows.Next() {
		var sr steeredRoute
		if err := rows.Scan(&sr.id, &sr.domain, &sr.anchorNodeID, &sr.dnsProviderID, &sr.ttlSeconds); err == nil {
			targets = append(targets, sr)
		}
	}
	rows.Close()

	for _, sr := range targets {
		select {
		case <-ctx.Done():
			return
		default:
		}
		rctx, cancel := context.WithTimeout(ctx, perRouteTimeout)
		rc.reconcileRoute(rctx, db, sr)
		cancel()
		rc.cursor = sr.id
	}
	if len(targets) < routeLimit {
		rc.cursor = 0 // reached the end; wrap around next tick
	}
}

// reconcileRoute handles one route end to end: load creds + candidates,
// build the provider client, diff against the live zone, apply, persist.
func (rc *Reconciler) reconcileRoute(ctx context.Context, db *sql.DB, sr steeredRoute) {
	candidates, err := rc.loadCandidates(ctx, db, sr)
	if err != nil {
		rc.logger().Warn("dnssteer: load candidate nodes", "route_id", sr.id, "err", err)
		return
	}
	if len(candidates) == 0 {
		return
	}
	provider, zone, err := rc.providerFor(ctx, db, sr.dnsProviderID)
	var lookupErr providerLookupError
	if errors.As(err, &lookupErr) {
		rc.logger().Warn("dnssteer: provider lookup", "route_id", sr.id, "err", err)
		return
	}
	if err != nil {
		rc.recordAll(ctx, db, sr.id, candidates, err.Error())
		return
	}
	existing, err := provider.GetRecords(ctx, zone)
	if err != nil {
		rc.recordAll(ctx, db, sr.id, candidates, err.Error())
		return
	}

	rc.diffAndApply(ctx, db, provider, zone, sr, candidates, existing)
}

// providerLookupError wraps a failed dns_providers row read, as opposed to a
// credential problem worth surfacing in last_error.
type providerLookupError struct{ err error }

func (e providerLookupError) Error() string { return e.err.Error() }
func (e providerLookupError) Unwrap() error { return e.err }

// providerFor builds the Provider client and zone name for a dns_providers row.
func (rc *Reconciler) providerFor(ctx context.Context, db *sql.DB, providerID int64) (Provider, string, error) {
	var zone, slug, encCreds string
	if err := db.QueryRowContext(ctx,
		`SELECT name, provider, api_token_enc FROM dns_providers WHERE id = ?`, providerID,
	).Scan(&zone, &slug, &encCreds); err != nil {
		return nil, "", providerLookupError{err}
	}
	if rc.DecryptSecret == nil {
		return nil, "", errors.New("dns steering: decrypt helper not wired")
	}
	blob, err := rc.DecryptSecret(encCreds)
	if err != nil || blob == "" {
		return nil, "", errors.New("credential decrypt failed")
	}
	fields := caddyapi.DecodeDNSFields(slug, blob)
	if len(fields) == 0 {
		return nil, "", errors.New("credential blob unusable")
	}
	provider, err := rc.newProvider(slug, fields)
	if err != nil {
		return nil, "", err
	}
	return provider, zone, nil
}

// ownedRecord is a dns_steering_records row: a record this reconciler created.
type ownedRecord struct {
	routeID, nodeID, providerID int64
	name, value, recordID       string
}

// cleanupOrphans deletes owned records whose route was deleted, disabled or
// un-steered, whose provider/domain changed, or whose node no longer serves
// the route at that IP. Ownership is dropped only once the record is gone.
func (rc *Reconciler) cleanupOrphans(ctx context.Context, db *sql.DB) {
	rows, err := db.QueryContext(ctx, `
		SELECT o.route_id, o.node_id, o.dns_provider_id, o.record_name, o.record_value, o.record_id
		  FROM dns_steering_records o
		  LEFT JOIN routes r ON r.id = o.route_id
		 WHERE r.id IS NULL
		    OR r.dns_steering_enabled = 0
		    OR r.domain_verified = 0
		    OR r.status = 'disabled'
		    OR r.dns_provider_id IS NULL
		    OR r.dns_provider_id <> o.dns_provider_id
		    OR r.domain <> o.record_name
		    OR (r.caddy_node_id <> o.node_id AND NOT EXISTS (
		        SELECT 1 FROM route_node_assignments rna WHERE rna.route_id = o.route_id AND rna.node_id = o.node_id))
		    OR NOT EXISTS (SELECT 1 FROM caddy_nodes n WHERE n.id = o.node_id AND n.public_ip = o.record_value)
		 ORDER BY o.dns_provider_id LIMIT ?`, routeLimit)
	if err != nil {
		rc.logger().Warn("dnssteer: list orphaned records", "err", err)
		return
	}
	byProvider := map[int64][]ownedRecord{}
	var order []int64
	for rows.Next() {
		var o ownedRecord
		if err := rows.Scan(&o.routeID, &o.nodeID, &o.providerID, &o.name, &o.value, &o.recordID); err != nil {
			continue
		}
		if _, seen := byProvider[o.providerID]; !seen {
			order = append(order, o.providerID)
		}
		byProvider[o.providerID] = append(byProvider[o.providerID], o)
	}
	rows.Close()

	for _, pid := range order {
		if ctx.Err() != nil {
			return
		}
		pctx, cancel := context.WithTimeout(ctx, perRouteTimeout)
		rc.cleanupProvider(pctx, db, pid, byProvider[pid])
		cancel()
	}
}

func (rc *Reconciler) cleanupProvider(ctx context.Context, db *sql.DB, providerID int64, owned []ownedRecord) {
	provider, zone, err := rc.providerFor(ctx, db, providerID)
	if errors.Is(err, sql.ErrNoRows) {
		// Provider row deleted together with its credentials: nothing can
		// ever reach that zone again, so stop retrying.
		rc.logger().Warn("dnssteer: provider gone, abandoning owned records", "dns_provider_id", providerID, "count", len(owned))
		for _, o := range owned {
			rc.forgetOwned(ctx, db, o.routeID, o.nodeID, o.value)
		}
		return
	}
	if err != nil {
		rc.logger().Warn("dnssteer: cleanup provider", "dns_provider_id", providerID, "err", err)
		return
	}
	live, err := provider.GetRecords(ctx, zone)
	if err != nil {
		rc.logger().Warn("dnssteer: cleanup list records", "dns_provider_id", providerID, "err", err)
		return
	}
	for _, o := range owned {
		rec, found := matchOwned(o, live)
		if found {
			if _, err := provider.DeleteRecords(ctx, zone, []Record{rec}); err != nil {
				rc.logger().Warn("dnssteer: cleanup delete", "route_id", o.routeID, "node_id", o.nodeID, "err", err)
				continue
			}
			auditWrite(ctx, db, rc.logger(), "dns.steering.record_removed", o.routeID, o.nodeID, o.value, o.name)
		}
		rc.forgetOwned(ctx, db, o.routeID, o.nodeID, o.value)
		if _, err := db.ExecContext(ctx,
			`UPDATE dns_steering_state SET present=0, last_synced_at=CURRENT_TIMESTAMP WHERE route_id=? AND node_id=? AND record_value=?`,
			o.routeID, o.nodeID, o.value); err != nil {
			rc.logger().Warn("dnssteer: persist state", "route_id", o.routeID, "node_id", o.nodeID, "err", err)
		}
	}
}

// matchOwned finds the live record for o: by provider ID when we have one, else
// by name+value (rows backfilled before IDs were stored).
func matchOwned(o ownedRecord, live []Record) (Record, bool) {
	for _, rec := range live {
		if o.recordID != "" {
			if rec.ID == o.recordID {
				return rec, true
			}
			continue
		}
		if rec.Name == o.name && rec.Value == o.value {
			return rec, true
		}
	}
	return Record{}, false
}

func (rc *Reconciler) rememberOwned(ctx context.Context, db *sql.DB, sr steeredRoute, nodeID int64, value, recordID string) {
	rc.forgetOwned(ctx, db, sr.id, nodeID, value)
	if _, err := db.ExecContext(ctx,
		`INSERT INTO dns_steering_records (route_id, node_id, dns_provider_id, record_name, record_value, record_id) VALUES (?, ?, ?, ?, ?, ?)`,
		sr.id, nodeID, sr.dnsProviderID, sr.domain, value, recordID); err != nil {
		rc.logger().Warn("dnssteer: persist owned record", "route_id", sr.id, "node_id", nodeID, "err", err)
	}
}

func (rc *Reconciler) forgetOwned(ctx context.Context, db *sql.DB, routeID, nodeID int64, value string) {
	if _, err := db.ExecContext(ctx,
		`DELETE FROM dns_steering_records WHERE route_id=? AND node_id=? AND record_value=?`,
		routeID, nodeID, value); err != nil {
		rc.logger().Warn("dnssteer: drop owned record", "route_id", routeID, "node_id", nodeID, "err", err)
	}
}

// loadCandidates returns every node that can host this route: the anchor
// (routes.caddy_node_id) plus any route_node_assignments fan-out peer.
func (rc *Reconciler) loadCandidates(ctx context.Context, db *sql.DB, sr steeredRoute) ([]nodeCandidate, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT n.id, COALESCE(n.public_ip,''), n.is_enabled, n.health_status
		  FROM caddy_nodes n WHERE n.id = ?
		UNION
		SELECT n.id, COALESCE(n.public_ip,''), n.is_enabled, n.health_status
		  FROM route_node_assignments rna
		  JOIN caddy_nodes n ON n.id = rna.node_id
		 WHERE rna.route_id = ?`, sr.anchorNodeID, sr.id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []nodeCandidate
	for rows.Next() {
		var c nodeCandidate
		var health string
		if err := rows.Scan(&c.id, &c.ip, &c.enabled, &health); err != nil {
			continue
		}
		if c.ip == "" || net.ParseIP(c.ip) == nil {
			continue // can't publish DNS for a node without a valid public IP
		}
		c.healthy = health == "healthy"
		out = append(out, c)
	}
	return out, rows.Err()
}

// action is one record mutation the diff decided on.
type action struct {
	kind   string // "add" or "remove"
	nodeID int64
	rec    Record // add: synthesized target (no ID yet); remove: existing provider record (has ID)
}

// planActions is the pure diff: given the route's candidate nodes and the
// provider's existing records for recordName, decide what to add/remove.
// Side-effect-free so it's directly unit-testable without a DB or provider.
func planActions(recordName string, candidates []nodeCandidate, existing []Record) []action {
	existingByIP := make(map[string]Record, len(existing))
	for _, rec := range existing {
		if rec.Name != recordName {
			continue
		}
		existingByIP[rec.Value] = rec
	}

	var toAdd, toRemove []action
	for _, c := range candidates {
		rec, present := existingByIP[c.ip]
		wantPresent := c.enabled && c.healthy
		switch {
		case wantPresent && !present:
			toAdd = append(toAdd, action{kind: "add", nodeID: c.id, rec: Record{Type: recordType(c.ip), Name: recordName, Value: c.ip}})
		case !wantPresent && present:
			toRemove = append(toRemove, action{kind: "remove", nodeID: c.id, rec: rec})
		}
	}

	// Fail-static: never apply a plan that would drop every record for this
	// name. A stale A record beats NXDOMAIN for clients mid-flight, and every
	// candidate flipping unhealthy at once is far more likely to be a
	// health-check blind spot than a real simultaneous full outage.
	if len(toAdd) == 0 && len(toRemove) > 0 && len(toRemove) == len(existingByIP) {
		sort.Slice(toRemove, func(i, j int) bool { return toRemove[i].nodeID < toRemove[j].nodeID })
		toRemove = toRemove[1:] // keep the lowest node ID's record
	}

	return append(toAdd, toRemove...)
}

func recordType(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed != nil && parsed.To4() != nil {
		return "A"
	}
	return "AAAA"
}

// diffAndApply computes the plan and executes each action against provider,
// persisting the per-node outcome to dns_steering_state and auditing changes.
func (rc *Reconciler) diffAndApply(ctx context.Context, db *sql.DB, provider Provider, zone string, sr steeredRoute, candidates []nodeCandidate, existing []Record) {
	ttl := time.Duration(sr.ttlSeconds) * time.Second
	for _, a := range planActions(sr.domain, candidates, existing) {
		switch a.kind {
		case "add":
			rec := a.rec
			rec.TTL = ttl
			created, err := provider.AppendRecords(ctx, zone, []Record{rec})
			if err != nil || len(created) == 0 {
				msg := "append failed"
				if err != nil {
					msg = err.Error()
				}
				rc.recordError(ctx, db, sr.id, a.nodeID, msg)
				continue
			}
			rc.rememberOwned(ctx, db, sr, a.nodeID, rec.Value, created[0].ID)
			rc.recordSuccess(ctx, db, sr.id, a.nodeID, rec.Value, true)
			auditWrite(ctx, db, rc.logger(), "dns.steering.record_added", sr.id, a.nodeID, rec.Value, sr.domain)
		case "remove":
			if _, err := provider.DeleteRecords(ctx, zone, []Record{a.rec}); err != nil {
				rc.recordError(ctx, db, sr.id, a.nodeID, err.Error())
				continue
			}
			rc.forgetOwned(ctx, db, sr.id, a.nodeID, a.rec.Value)
			rc.recordSuccess(ctx, db, sr.id, a.nodeID, a.rec.Value, false)
			auditWrite(ctx, db, rc.logger(), "dns.steering.record_removed", sr.id, a.nodeID, a.rec.Value, sr.domain)
		}
	}
}

func auditWrite(ctx context.Context, db *sql.DB, logger *slog.Logger, action string, routeID, nodeID int64, ip, domain string) {
	audit.Write(ctx, db, logger, nil, audit.Entry{
		ActorType: audit.ActorSystem, Action: action, Entity: "route",
		EntityID: strconv.FormatInt(routeID, 10),
		Meta:     map[string]any{"node_id": nodeID, "ip": ip, "domain": domain},
	})
}

func (rc *Reconciler) recordAll(ctx context.Context, db *sql.DB, routeID int64, candidates []nodeCandidate, msg string) {
	for _, c := range candidates {
		rc.recordError(ctx, db, routeID, c.id, msg)
	}
}

// recordSuccess and recordError use UPDATE-then-insert-on-no-match instead of
// an ON DUPLICATE KEY / ON CONFLICT upsert so the same query works unmodified
// against both MySQL and SQLite (see internal/store.Driver for why those two
// dialects otherwise need separate SQL).

func (rc *Reconciler) recordSuccess(ctx context.Context, db *sql.DB, routeID, nodeID int64, ip string, present bool) {
	res, err := db.ExecContext(ctx,
		`UPDATE dns_steering_state SET record_value=?, present=?, last_synced_at=CURRENT_TIMESTAMP, last_error=NULL WHERE route_id=? AND node_id=?`,
		ip, present, routeID, nodeID)
	if err == nil {
		if n, _ := res.RowsAffected(); n > 0 {
			return
		}
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO dns_steering_state (route_id, node_id, record_value, present, last_synced_at, last_error) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, NULL)`,
		routeID, nodeID, ip, present); err != nil {
		rc.logger().Warn("dnssteer: persist state", "route_id", routeID, "node_id", nodeID, "err", err)
	}
}

func (rc *Reconciler) recordError(ctx context.Context, db *sql.DB, routeID, nodeID int64, msg string) {
	res, err := db.ExecContext(ctx,
		`UPDATE dns_steering_state SET last_error=? WHERE route_id=? AND node_id=?`, msg, routeID, nodeID)
	if err == nil {
		if n, _ := res.RowsAffected(); n > 0 {
			return
		}
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO dns_steering_state (route_id, node_id, record_value, present, last_error) VALUES (?, ?, '', 0, ?)`,
		routeID, nodeID, msg); err != nil {
		rc.logger().Warn("dnssteer: persist error state", "route_id", routeID, "node_id", nodeID, "err", err)
	}
}

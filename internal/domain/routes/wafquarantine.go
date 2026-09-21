// Per-route quarantine for custom WAF directives a node's /load refused.
package routes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// wafIsolationLimit bounds how many extra /load calls one refused config may
// cost. Above it the whole suspect set is parked in a single retry instead.
const wafIsolationLimit = 6

// wafFingerprint identifies one route's effective directive text, so an edited
// set gets another chance without an operator clearing the flag by hand.
func wafFingerprint(directives string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(directives)))
	return hex.EncodeToString(sum[:])
}

// wafCandidates lists the indices of routes carrying custom WAF directives -
// the only routes whose config can be held back without dropping the site.
func wafCandidates(built []caddyapi.Route) []int {
	var out []int
	for i := range built {
		if strings.TrimSpace(built[i].WAFDirectives) != "" {
			out = append(out, i)
		}
	}
	return out
}

// applyWAFQuarantine strips directives a node already refused, as long as they
// are still the exact text that was refused. Mutates built in place.
func (s *Service) applyWAFQuarantine(ctx context.Context, built []caddyapi.Route, ids []int64) {
	cand := wafCandidates(built)
	if s.DB == nil || len(cand) == 0 || len(ids) != len(built) {
		return
	}
	ph := make([]string, 0, len(cand))
	args := make([]any, 0, len(cand))
	for _, i := range cand {
		ph = append(ph, "?")
		args = append(args, ids[i])
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, COALESCE(waf_quarantine_fingerprint,''), COALESCE(waf_quarantine_reason,'')
		   FROM routes WHERE waf_quarantined_at IS NOT NULL AND id IN (`+strings.Join(ph, ",")+`)`, args...)
	if err != nil {
		if s.Logger != nil {
			s.Logger.Warn("WAF quarantine state unreadable; directives emitted as stored", "err", err)
		}
		return
	}
	parked := map[int64][2]string{}
	for rows.Next() {
		var id int64
		var fp, reason string
		if err := rows.Scan(&id, &fp, &reason); err == nil {
			parked[id] = [2]string{fp, reason}
		}
	}
	rows.Close()
	if len(parked) == 0 {
		return
	}
	notes := map[int64]compileNote{}
	for _, i := range cand {
		p, ok := parked[ids[i]]
		if !ok || p[0] != wafFingerprint(built[i].WAFDirectives) {
			continue
		}
		built[i].WAFDirectives = ""
		notes[ids[i]] = compileNote{compileQuarantined, "custom WAF directives held back: " + p[1]}
	}
	if len(notes) > 0 {
		s.recordCompileNotes(ctx, nil, notes)
	}
}

// isConfigRejection distinguishes "the node refused this config" from "the node
// was unreachable". Only the former can be blamed on a route.
func isConfigRejection(err error) bool {
	return err != nil && strings.Contains(err.Error(), "400")
}

// isolateWAFFailure retries a refused /load without the custom WAF directives
// that caused it, so the rest of the node still publishes. Returns the config
// that actually loaded, or nil when the fault is not (or not only) WAF.
//
// A rejected /load is atomic, so the node stays on whatever last loaded; each
// probe therefore either advances the live config or leaves it where it was.
func (s *Service) isolateWAFFailure(ctx context.Context, nodeID int64, client *caddyapi.Client, np *nodePush, loadErr error) *nodePush {
	cand := wafCandidates(np.built)
	if !isConfigRejection(loadErr) || len(cand) == 0 || len(np.routeIDs) != len(np.built) {
		return nil
	}
	// Baseline: every custom WAF block dropped. Still refused => the fault is
	// somewhere else and the original error must stand.
	base := make([]caddyapi.Route, len(np.built))
	copy(base, np.built)
	for _, i := range cand {
		base[i].WAFDirectives = ""
	}
	if err := client.Load(ctx, np.render(base)); err != nil {
		return nil
	}
	accepted := base
	if len(cand) > wafIsolationLimit {
		for _, i := range cand {
			s.quarantineRouteWAF(ctx, np.routeIDs[i], np.built[i].WAFDirectives,
				fmt.Errorf("node refused the config and too many routes carry custom WAF directives to test one by one: %w", loadErr))
		}
		return np.with(accepted)
	}
	// Add each suspect back on its own; whatever the node refuses is parked.
	for _, i := range cand {
		next := make([]caddyapi.Route, len(accepted))
		copy(next, accepted)
		next[i].WAFDirectives = np.built[i].WAFDirectives
		if err := client.Load(ctx, np.render(next)); err != nil {
			s.quarantineRouteWAF(ctx, np.routeIDs[i], np.built[i].WAFDirectives, err)
			continue
		}
		accepted = next
	}
	return np.with(accepted)
}

// with returns the push snapshot for an already-loaded route set.
func (np *nodePush) with(built []caddyapi.Route) *nodePush {
	return &nodePush{cfg: np.render(built), built: built, routeIDs: np.routeIDs,
		apiURL: np.apiURL, settings: np.settings}
}

// quarantineRouteWAF parks one route's directives and records why, the same way
// an unsafe stream destination is parked.
func (s *Service) quarantineRouteWAF(ctx context.Context, routeID int64, directives string, cause error) {
	reason := cause.Error()
	if len(reason) > 255 {
		reason = reason[:255]
	}
	if s.DB != nil {
		if _, err := s.DB.ExecContext(ctx,
			`UPDATE routes SET waf_quarantined_at = `+store.Now()+`,
			        waf_quarantine_reason = ?, waf_quarantine_fingerprint = ? WHERE id = ?`,
			reason, wafFingerprint(directives), routeID); err != nil && s.Logger != nil {
			s.Logger.Error("WAF quarantine flag failed", "route_id", routeID, "err", err)
		}
		s.recordCompileNotes(ctx, nil, map[int64]compileNote{
			routeID: {compileQuarantined, "custom WAF directives held back: " + reason},
		})
	}
	if s.Logger != nil {
		s.Logger.Warn("route WAF directives quarantined: the node refused the config",
			"route_id", routeID, "reason", reason)
	}
	audit.Write(ctx, s.DB, s.Logger, nil, audit.Entry{
		ActorType: audit.ActorSystem,
		Action:    "route.waf_directives.quarantined",
		Entity:    "route",
		EntityID:  strconv.FormatInt(routeID, 10),
		Meta:      map[string]any{"reason": reason},
	})
}

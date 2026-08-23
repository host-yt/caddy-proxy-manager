// Layer-4 stream build and destination screening.
package routes

import (
	"context"
	"fmt"
	"strings"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
	"github.com/host-yt/caddy-proxy-manager/internal/streamguard"
)

// buildStreamsForNode reads the stream_routes table for one node and
// returns caddyapi.StreamRoute values ready for the L4 builder. Joins on
// services for the backend_ip (admin-only; stream routes never expose this
// to the customer). Also loads stream_upstreams and advanced columns added
// in migration 00061. Every destination is re-screened here, so a row stored
// before a target became control-plane infrastructure cannot be re-emitted.
func (s *Service) buildStreamsForNode(ctx context.Context, nodeID int64) ([]caddyapi.StreamRoute, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT sr.id, sr.protocol, sr.listen_port, sr.upstream_port,
		        COALESCE(NULLIF(sr.backend_ip_override,''), sv.backend_ip),
		        COALESCE(sr.match_mode,'any'),
		        COALESCE(sr.match_values,''),
		        COALESCE(sr.lb_policy,'round_robin'),
		        COALESCE(sr.proxy_proto_in,'none'),
		        COALESCE(sr.proxy_proto_out,'none'),
		        COALESCE(sr.cidr_allow,''),
		        COALESCE(sr.cidr_deny,'')
		 FROM stream_routes sr JOIN services sv ON sv.id = sr.service_id
		 WHERE sr.caddy_node_id = ? AND sr.status = 'active' AND sr.quarantined_at IS NULL
		 ORDER BY sr.listen_port ASC`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []caddyapi.StreamRoute
	for rows.Next() {
		var r caddyapi.StreamRoute
		var matchValuesCSV, cidrAllow, cidrDeny string
		if err := rows.Scan(
			&r.ID, &r.Protocol, &r.ListenPort, &r.UpstreamPort, &r.UpstreamIP,
			&r.MatchMode, &matchValuesCSV, &r.LBPolicy,
			&r.ProxyProtoIn, &r.ProxyProtoOut,
			&cidrAllow, &cidrDeny,
		); err != nil {
			continue
		}
		r.MatchValues = splitCSV(matchValuesCSV)
		r.CIDRAllow = splitCSV(cidrAllow)
		r.CIDRDeny = splitCSV(cidrDeny)
		out = append(out, r)
	}
	if len(out) == 0 {
		return out, nil
	}
	// Attach multi-upstreams; routes without rows keep the legacy single-upstream.
	s.attachStreamUpstreams(ctx, out)
	return s.screenStreams(ctx, out)
}

// screenStreams re-validates every stream destination at emission time and
// quarantines rows that now point at node or control-plane addresses. A deny
// set that cannot be loaded fails the whole push closed.
func (s *Service) screenStreams(ctx context.Context, in []caddyapi.StreamRoute) ([]caddyapi.StreamRoute, error) {
	infra, err := streamguard.LoadInfraTargets(ctx, s.DB)
	if err != nil {
		return nil, fmt.Errorf("stream target screening unavailable: %w", err)
	}
	out, rejected := screenStreamSet(ctx, infra, in)
	for _, rej := range rejected {
		s.quarantineStream(ctx, rej.route, rej.cause)
	}
	return out, nil
}

// streamReject pairs a rejected stream with why it was rejected.
type streamReject struct {
	route caddyapi.StreamRoute
	cause error
}

// screenStreamSet splits streams into emittable (destinations pinned to a
// validated literal) and rejected. Pure, so the policy is testable without a DB.
func screenStreamSet(ctx context.Context, infra *streamguard.InfraTargets, in []caddyapi.StreamRoute) ([]caddyapi.StreamRoute, []streamReject) {
	out := make([]caddyapi.StreamRoute, 0, len(in))
	var rejected []streamReject
	for _, r := range in {
		pinnedIP, perr := infra.ScreenAndPin(ctx, r.UpstreamIP, r.UpstreamPort)
		if perr != nil {
			rejected = append(rejected, streamReject{r, perr})
			continue
		}
		r.UpstreamIP = pinnedIP
		var bad error
		for i, u := range r.Upstreams {
			pinned, uerr := infra.ScreenAndPinAddress(ctx, u.Address)
			if uerr != nil {
				bad = uerr
				break
			}
			r.Upstreams[i].Address = pinned
		}
		if bad != nil {
			rejected = append(rejected, streamReject{r, bad})
			continue
		}
		out = append(out, r)
	}
	return out, rejected
}

// quarantineStream parks an unsafe stream so it stops being re-emitted, and
// leaves a visible trail instead of silently dropping it.
func (s *Service) quarantineStream(ctx context.Context, r caddyapi.StreamRoute, cause error) {
	reason := cause.Error()
	if len(reason) > 255 {
		reason = reason[:255]
	}
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE stream_routes SET quarantined_at = `+store.Now()+`, quarantine_reason = ? WHERE id = ?`,
		reason, r.ID); err != nil && s.Logger != nil {
		s.Logger.Error("stream quarantine flag failed", "stream_id", r.ID, "err", err)
	}
	if s.Logger != nil {
		s.Logger.Warn("stream quarantined: unsafe destination", "stream_id", r.ID,
			"listen_port", r.ListenPort, "reason", reason)
	}
	audit.Write(ctx, s.DB, s.Logger, nil, audit.Entry{
		ActorType: audit.ActorSystem,
		Action:    "stream.quarantined",
		Entity:    "stream_route",
		EntityID:  fmt.Sprintf("%d", r.ID),
		Meta:      map[string]any{"reason": reason, "listen_port": r.ListenPort},
	})
}

// attachStreamUpstreams loads stream_upstreams rows and maps them onto the
// built StreamRoute slice by ID. Routes without upstream rows use the
// legacy UpstreamIP:UpstreamPort path.
func (s *Service) attachStreamUpstreams(ctx context.Context, built []caddyapi.StreamRoute) {
	if len(built) == 0 {
		return
	}
	// Collect IDs for IN(...) query - avoids N+1.
	ids := make([]int64, len(built))
	idx := make(map[int64]int, len(built))
	for i, r := range built {
		ids[i] = r.ID
		idx[r.ID] = i
	}

	// Build parameterized IN clause.
	placeholders := strings.Repeat("?,", len(ids))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}

	rows, err := s.DB.QueryContext(ctx,
		`SELECT stream_route_id, address, weight
		 FROM stream_upstreams
		 WHERE stream_route_id IN (`+placeholders+`)
		 ORDER BY stream_route_id ASC, sort_order ASC, id ASC`, args...)
	if err != nil {
		s.Logger.Warn("stream_upstreams load failed; routes stay single-dial", "err", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var routeID int64
		var u caddyapi.StreamUpstream
		if err := rows.Scan(&routeID, &u.Address, &u.Weight); err != nil {
			continue
		}
		if i, ok := idx[routeID]; ok {
			built[i].Upstreams = append(built[i].Upstreams, u)
		}
	}
}

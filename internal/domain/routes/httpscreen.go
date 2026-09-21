// Emission-time screening of tenant-controlled HTTP proxy targets.
package routes

import (
	"context"
	"fmt"
	"strings"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
	"github.com/host-yt/caddy-proxy-manager/internal/streamguard"
)

// httpDrop records one target removed from the emitted config.
type httpDrop struct {
	route caddyapi.Route
	part  string
	cause error
}

// screenHTTPTargets re-screens every dial target of the built routes at
// emission time, so a row stored before its target became control-plane
// infrastructure (or stored through a path that predates the screener) is not
// re-emitted. A deny set that cannot be loaded fails the whole push closed.
func (s *Service) screenHTTPTargets(ctx context.Context, built []caddyapi.Route, ids []int64) ([]caddyapi.Route, []int64, error) {
	if len(built) == 0 {
		return built, ids, nil
	}
	infra, err := streamguard.LoadInfraTargets(ctx, s.DB)
	if err != nil {
		return nil, nil, fmt.Errorf("http target screening unavailable: %w", err)
	}
	outRoutes, outIDs, drops := screenHTTPSet(infra, built, ids)
	for _, d := range drops {
		if s.Logger != nil {
			s.Logger.Warn("unsafe HTTP target dropped from config",
				"part", d.part, "route_id", d.route.ID, "reason", d.cause.Error())
		}
		if d.part != "primary backend" {
			continue
		}
		// A dropped primary means the host stops being served: audit it.
		audit.Write(ctx, s.DB, s.Logger, nil, audit.Entry{
			ActorType: audit.ActorSystem,
			Action:    "route.blocked_target",
			Entity:    "route",
			EntityID:  d.route.ID,
			Meta:      map[string]any{"reason": d.cause.Error(), "backend": d.route.UpstreamIP},
		})
	}
	return outRoutes, outIDs, nil
}

// screenHTTPSet splits built routes into emittable and dropped. Pure, so the
// policy is testable without a DB. ids follows the same permutation as built.
func screenHTTPSet(infra *streamguard.InfraTargets, built []caddyapi.Route, ids []int64) ([]caddyapi.Route, []int64, []httpDrop) {
	outRoutes := make([]caddyapi.Route, 0, len(built))
	outIDs := make([]int64, 0, len(ids))
	var drops []httpDrop
	for i, r := range built {
		if r.Kind == "redirect" {
			outRoutes, outIDs = append(outRoutes, r), append(outIDs, idAt(ids, i))
			continue
		}
		if err := screenEmitted(infra, r.UpstreamIP, r.UpstreamPort); err != nil {
			drops = append(drops, httpDrop{r, "primary backend", err})
			continue
		}
		ups := r.Upstreams[:0:0]
		for _, u := range r.Upstreams {
			if err := screenEmitted(infra, u.Host, u.Port); err != nil {
				drops = append(drops, httpDrop{r, "upstream", err})
				continue
			}
			ups = append(ups, u)
		}
		r.Upstreams = ups
		rules := r.LocationRules[:0:0]
		for _, lr := range r.LocationRules {
			if lr.Action == "proxy" {
				if err := screenEmitted(infra, lr.UpstreamHost, lr.UpstreamPort); err != nil {
					drops = append(drops, httpDrop{r, "location rule", err})
					continue
				}
			}
			rules = append(rules, lr)
		}
		r.LocationRules = rules
		outRoutes, outIDs = append(outRoutes, r), append(outIDs, idAt(ids, i))
	}
	return outRoutes, outIDs, drops
}

// screenEmitted applies the deny set without resolving: tunnel and container
// backends resolve node-side, and a DNS blip must not silently delete live
// routes. The write path does the resolving screen.
func screenEmitted(infra *streamguard.InfraTargets, host string, port int) error {
	if strings.TrimSpace(host) == "" {
		return nil
	}
	return infra.ScreenHTTPTargetLiteral(host, port)
}

func idAt(ids []int64, i int) int64 {
	if i < len(ids) {
		return ids[i]
	}
	return 0
}

// firstErrOf returns the first non-nil error.
func firstErrOf(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

package routes

import (
	"context"
	"database/sql"
	"regexp"
	"strings"

	"github.com/host-yt/caddy-proxy-manager/internal/wafevents"
)

// rule_id is free text in the suppress form; only a plain ID or ID range may
// reach seclang, anything else could smuggle directives into the node config.
var wafRuleIDRe = regexp.MustCompile(`^[0-9]{1,9}(-[0-9]{1,9})?$`)

// loadWAFSuppressions returns the active suppressions once per build. A read
// error degrades to "none" so a push never fails on this.
func (s *Service) loadWAFSuppressions(ctx context.Context) []wafevents.Suppression {
	if s.DB == nil {
		return nil
	}
	sups, err := wafevents.New(func() *sql.DB { return s.DB }).ListSuppressions(ctx, nil)
	if err != nil && s.Logger != nil {
		s.Logger.Warn("waf suppressions load", "err", err)
	}
	return sups
}

// wafSuppressionDirectives renders SecRuleRemoveById lines for the suppressions
// that apply to routeID (global or scoped to it). A suppressed rule must stop
// blocking on the node, not just disappear from the events page (#14).
func wafSuppressionDirectives(sups []wafevents.Suppression, routeID int64) string {
	var b strings.Builder
	seen := map[string]bool{}
	for _, sup := range sups {
		if sup.RouteID.Valid && sup.RouteID.Int64 != routeID {
			continue
		}
		id := strings.TrimSpace(sup.RuleID)
		if seen[id] || !wafRuleIDRe.MatchString(id) {
			continue
		}
		seen[id] = true
		b.WriteString("SecRuleRemoveById ")
		b.WriteString(id)
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// appendWAFDirectives joins the operator's directives with generated ones,
// keeping both after the CRS include (see caddyapi.BuildRoute).
func appendWAFDirectives(base, extra string) string {
	base = strings.TrimSpace(base)
	if extra == "" {
		return base
	}
	if base == "" {
		return extra
	}
	return base + "\n" + extra
}

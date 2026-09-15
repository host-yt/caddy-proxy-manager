package routes

import (
	"database/sql"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/wafevents"
)

func TestWAFSuppressionDirectives(t *testing.T) {
	route := func(id int64) sql.NullInt64 { return sql.NullInt64{Int64: id, Valid: true} }
	sups := []wafevents.Suppression{
		{RuleID: "942100"},                    // global
		{RuleID: "920350", RouteID: route(7)}, // this route
		{RuleID: "941100", RouteID: route(8)}, // other route
		{RuleID: "942100"},                    // duplicate
		{RuleID: "930100-930199"},             // range is valid seclang
		{RuleID: "942100; SecRuleEngine Off"}, // injection attempt
		{RuleID: "abc"},
	}
	got := wafSuppressionDirectives(sups, 7)
	want := "SecRuleRemoveById 942100\nSecRuleRemoveById 920350\nSecRuleRemoveById 930100-930199"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	if got := wafSuppressionDirectives(nil, 7); got != "" {
		t.Fatalf("no suppressions must yield empty, got %q", got)
	}
	if got := appendWAFDirectives("  SecRuleRemoveById 1  ", "SecRuleRemoveById 2"); got != "SecRuleRemoveById 1\nSecRuleRemoveById 2" {
		t.Fatalf("append: %q", got)
	}
	if got := appendWAFDirectives("", ""); got != "" {
		t.Fatalf("append empty: %q", got)
	}
}

package view

import (
	"strings"
	"testing"
)

// TestAdminTemplatesParse ensures every admin template (incl. the AI settings
// pane) parses. A bad {{...}} would fail here rather than at runtime.
func TestAdminTemplatesParse(t *testing.T) {
	if _, err := LoadAdminTemplates(); err != nil {
		t.Fatalf("LoadAdminTemplates: %v", err)
	}
}

// TestSettingsTemplateExecutesAI renders the settings partial with the AI block
// populated to catch field/range mismatches in the AI assistant pane.
func TestSettingsTemplateExecutesAI(t *testing.T) {
	at, err := LoadAdminTemplates()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// Minimal map mirroring the AI subset the template reads. The settings
	// template tolerates zero values for unrelated sections.
	data := map[string]any{
		"CSRF":     "x",
		"CSPNonce": "n",
		"AI": map[string]any{
			"DefaultProvider": "anthropic",
			"Providers": []map[string]any{
				{"ID": "anthropic", "Label": "Anthropic (Claude)", "Configured": true},
				{"ID": "openai", "Label": "OpenAI", "Configured": false},
			},
		},
	}
	var sb strings.Builder
	if err := at.t.ExecuteTemplate(&sb, "settings", data); err != nil {
		t.Fatalf("execute settings: %v", err)
	}
	out := sb.String()
	if !strings.Contains(out, "AI assistant") || !strings.Contains(out, "/admin/settings/ai") {
		t.Fatalf("AI pane not rendered")
	}
}

// TestHostsNewTemplateExecutes renders the add-host form both with node
// groups (full form + group select) and without (first-run wizard card),
// catching field mismatches the parse-only test can't see.
func TestHostsNewTemplateExecutes(t *testing.T) {
	at, err := LoadAdminTemplates()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	form := map[string]any{
		"Kind": "proxy", "Domain": "", "BackendIP": "", "Port": "",
		"UpstreamScheme": "http", "NodeGroupID": "", "NodeID": "",
		"SSL": true, "WebSocket": true, "RedirectURL": "", "RedirectCode": "308",
		"Tag": "", "External": false, "ExternalHost": "", "UpstreamHostHeader": "",
		"WildcardEnabled": false, "WildcardZone": "",
	}
	withGroups := map[string]any{
		"CSRF": "x", "CSPNonce": "n", "Form": form,
		"NodeGroups": []map[string]any{
			{"ID": 1, "Name": "eu-west", "Mode": "active_active", "Nodes": []map[string]any{
				{"ID": 13, "Name": "node13", "Hostname": "n13.example.com", "IP": "1.2.3.4"},
				{"ID": 14, "Name": "node14", "Hostname": "n14.example.com", "IP": "5.6.7.8"},
			}},
		},
		"Groups": []map[string]any{}, "CFViews": nil,
	}
	var sb strings.Builder
	if err := at.t.ExecuteTemplate(&sb, "hosts_new", withGroups); err != nil {
		t.Fatalf("execute hosts_new with groups: %v", err)
	}
	out := sb.String()
	if !strings.Contains(out, "node_group_id") || !strings.Contains(out, "active_active") {
		t.Fatalf("group select not rendered")
	}

	empty := map[string]any{"CSRF": "x", "CSPNonce": "n", "Form": form, "NodeGroups": nil}
	sb.Reset()
	if err := at.t.ExecuteTemplate(&sb, "hosts_new", empty); err != nil {
		t.Fatalf("execute hosts_new empty: %v", err)
	}
	if !strings.Contains(sb.String(), "No Caddy nodes are ready yet") {
		t.Fatalf("first-run wizard not rendered")
	}
}

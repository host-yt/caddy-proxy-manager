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

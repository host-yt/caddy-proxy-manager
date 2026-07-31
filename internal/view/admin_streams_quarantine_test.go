package view

import (
	"strings"
	"testing"
)

// A quarantined stream must explain itself in the panel: status alone leaves an
// operator with no idea what to fix.
func TestStreamTemplatesShowQuarantineReason(t *testing.T) {
	at, err := LoadAdminTemplates()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	const reason = "backend port 2019 is reserved for the node admin API"
	stream := map[string]any{
		"ID": 1, "Protocol": "tcp", "ListenPort": 5000, "UpstreamPort": 2019,
		"BackendIP": "10.0.0.5", "NodeName": "node1", "NodeHostname": "n1.example.com",
		"Status": "quarantined", "Quarantined": true, "QuarantineReason": reason,
		"Tag": "", "CreatedAt": "", "MatchMode": "any", "MatchValues": "",
		"LBPolicy": "round_robin", "ProxyProtoIn": "none", "ProxyProtoOut": "none",
	}

	var list strings.Builder
	if err := at.t.ExecuteTemplate(&list, "streams", map[string]any{
		"CSRF": "x", "CSPNonce": "n", "ModuleAvailable": true,
		"Streams": []map[string]any{stream},
		"Nodes":   []map[string]any{},
		"Form": map[string]any{"Protocol": "tcp", "MatchMode": "any", "LBPolicy": "round_robin",
			"ProxyProtoIn": "none", "ProxyProtoOut": "none", "ListenPort": "", "UpstreamPort": "",
			"BackendIP": "", "NodeID": "", "Tag": "", "MatchValues": "", "CIDRAllow": "", "CIDRDeny": "",
			"UpstreamsRaw": ""},
	}); err != nil {
		t.Fatalf("execute streams: %v", err)
	}
	if out := list.String(); !strings.Contains(out, reason) || !strings.Contains(out, "/recheck") {
		t.Error("stream list must show the quarantine reason and offer a re-check")
	}

	var edit strings.Builder
	if err := at.t.ExecuteTemplate(&edit, "streams_edit", map[string]any{
		"CSRF": "x", "CSPNonce": "n", "Stream": stream,
		"Upstreams": []map[string]any{}, "Nodes": []map[string]any{},
	}); err != nil {
		t.Fatalf("execute streams_edit: %v", err)
	}
	out := edit.String()
	if !strings.Contains(out, reason) || !strings.Contains(out, "/admin/streams/1/recheck") {
		t.Error("stream edit page must show the quarantine reason and a re-check action")
	}
	if !strings.Contains(out, `name="backend_ip"`) || !strings.Contains(out, `name="upstream_port"`) {
		t.Error("stream edit page must let the operator fix the destination")
	}
}

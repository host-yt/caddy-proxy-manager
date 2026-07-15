package caddyapi

import (
	"encoding/json"
	"strings"
	"testing"
)

// tlsApp digs the tls app out of a BuildNodeConfig result.
func tlsApp(t *testing.T, cfg map[string]any) map[string]any {
	t.Helper()
	apps, _ := cfg["apps"].(map[string]any)
	tls, _ := apps["tls"].(map[string]any)
	if tls == nil {
		t.Fatal("apps.tls missing")
	}
	return tls
}

func TestBuildNodeConfig_ManualCertsLoadPEM(t *testing.T) {
	cfg := BuildNodeConfig(nil, NodeSettings{
		AskURL: "http://app:8080/internal/ask",
		ManualCerts: []ManualCertPEM{
			{CertPEM: "LEAF-PEM", KeyPEM: "KEY-PEM"},
			{CertPEM: "LEAF2\nCHAIN2", KeyPEM: "KEY2"},
		},
	})
	tls := tlsApp(t, cfg)
	certs, ok := tls["certificates"].(map[string]any)
	if !ok {
		t.Fatal("tls.certificates missing when manual certs present")
	}
	lp, ok := certs["load_pem"].([]any)
	if !ok || len(lp) != 2 {
		t.Fatalf("load_pem: want 2 entries, got %#v", certs["load_pem"])
	}
	b, _ := json.Marshal(lp)
	for _, want := range []string{
		`"certificate":"LEAF-PEM"`, `"key":"KEY-PEM"`,
		`"certificate":"LEAF2\nCHAIN2"`, `"key":"KEY2"`,
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("load_pem JSON missing %q\nfull: %s", want, b)
		}
	}
}

// A node with no manual certs must not emit a certificates key, so its config
// stays byte-identical to before this feature (drift-hash safety).
func TestBuildNodeConfig_NoManualCerts_NoCertificatesKey(t *testing.T) {
	cfg := BuildNodeConfig(nil, NodeSettings{AskURL: "http://app:8080/internal/ask"})
	if _, ok := tlsApp(t, cfg)["certificates"]; ok {
		t.Fatal("tls.certificates emitted with no manual certs")
	}
}

// A half-formed entry (missing cert or key) is dropped, not emitted - Caddy
// would reject the whole /load on a keyless cert, taking the node offline.
func TestBuildLoadPEM_SkipsIncomplete(t *testing.T) {
	got := buildLoadPEM([]ManualCertPEM{
		{CertPEM: "C", KeyPEM: ""},
		{CertPEM: "", KeyPEM: "K"},
		{CertPEM: "  ", KeyPEM: "K"},
		{CertPEM: "C2", KeyPEM: "K2"},
	})
	if len(got) != 1 {
		t.Fatalf("want 1 valid entry, got %d", len(got))
	}
	if buildLoadPEM(nil) != nil {
		t.Fatal("nil input must yield nil (omit the key)")
	}
}

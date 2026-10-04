package handlers

import "testing"

func TestParseExternalUpstreamURL(t *testing.T) {
	for _, raw := range []string{"https://kvm.example.net", "https://kvm.example.net/", "https://kvm.example.net:8443/a/b/"} {
		if _, err := parseExternalUpstreamURL(raw); err != nil {
			t.Errorf("%s: %v", raw, err)
		}
	}
	for _, raw := range []string{
		"http://kvm.example.net",
		"https://user:pw@kvm.example.net",
		"https://kvm.example.net/?token=x",
		"https://kvm.example.net/#frag",
		"https://kvm.example.net:0",
		"https://kvm.example.net:70000",
		"https://kvm.example.net/a%2F..",
		"https:///nohost",
		"kvm.example.net",
		"ftp://kvm.example.net",
	} {
		if _, err := parseExternalUpstreamURL(raw); err == nil {
			t.Errorf("%s: accepted, want rejected", raw)
		}
	}
}

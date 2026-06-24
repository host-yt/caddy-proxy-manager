package caddyapi

import (
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Guards the registry-driven provider JSON for representative shapes plus the
// legacy single-token Cloudflare compat path.
func TestProviderJSON(t *testing.T) {
	// DigitalOcean: single token, key auth_token (NOT api_token).
	do := providerJSON("digitalocean", map[string]string{"auth_token": "do-secret"})
	if do["name"] != "digitalocean" || do["auth_token"] != "do-secret" {
		t.Fatalf("digitalocean wrong: %#v", do)
	}
	if _, bad := do["api_token"]; bad {
		t.Fatalf("digitalocean must not emit api_token: %#v", do)
	}

	// Route53: multi-field; empty optional fields are omitted.
	r53 := providerJSON("route53", map[string]string{
		"access_key_id": "AKIA", "secret_access_key": "sk", "region": "us-east-1",
	})
	if r53["name"] != "route53" || r53["access_key_id"] != "AKIA" || r53["secret_access_key"] != "sk" || r53["region"] != "us-east-1" {
		t.Fatalf("route53 wrong: %#v", r53)
	}
	if _, has := r53["hosted_zone_id"]; has {
		t.Fatalf("route53 should omit empty hosted_zone_id: %#v", r53)
	}

	// Gandi: bearer_token deviation from the api_token convention.
	g := providerJSON("gandi", map[string]string{"bearer_token": "tok"})
	if g["name"] != "gandi" || g["bearer_token"] != "tok" {
		t.Fatalf("gandi wrong: %#v", g)
	}

	// Unknown slug -> nil so the caller drops the policy.
	if providerJSON("bogus", map[string]string{"x": "y"}) != nil {
		t.Fatalf("unknown provider must yield nil")
	}
}

// Legacy cloudflare rows hold a bare token; any other provider needs JSON.
func TestDecodeDNSFieldsLegacyCompat(t *testing.T) {
	if got := DecodeDNSFields("cloudflare", "legacy-bare-token"); !reflect.DeepEqual(got, map[string]string{"api_token": "legacy-bare-token"}) {
		t.Fatalf("legacy cloudflare compat wrong: %#v", got)
	}
	blob, _ := EncodeDNSFields(map[string]string{"token": "desec-tok"})
	if got := DecodeDNSFields("desec", blob); got["token"] != "desec-tok" {
		t.Fatalf("desec JSON round-trip wrong: %#v", got)
	}
	if DecodeDNSFields("desec", "not-json") != nil {
		t.Fatalf("non-cloudflare bare blob must be nil")
	}
}

func TestValidateDNSFields(t *testing.T) {
	if _, err := ValidateDNSFields("porkbun", map[string]string{"api_key": "k"}); err == nil {
		t.Fatalf("porkbun missing api_secret_key should error")
	}
	if _, err := ValidateDNSFields("bogus", map[string]string{}); err == nil {
		t.Fatalf("unknown slug should error")
	}
	clean, err := ValidateDNSFields("route53", map[string]string{"access_key_id": "a", "secret_access_key": "b", "ignored": "z"})
	if err != nil || len(clean) != 2 {
		t.Fatalf("route53 required-only should pass and drop unknown keys: %v %#v", err, clean)
	}
}

// The xcaddy --with caddy-dns/<module> list in the edge image MUST equal the
// registry CaddyModule set, else a selected provider's module is missing and
// Caddy rejects the whole /load.
func TestDockerfileModulesMatchRegistry(t *testing.T) {
	b, err := os.ReadFile("../../deploy/caddy/Dockerfile")
	if err != nil {
		t.Skipf("dockerfile not found: %v", err)
	}
	re := regexp.MustCompile(`caddy-dns/([a-z0-9]+)`)
	var docker []string
	for _, m := range re.FindAllStringSubmatch(string(b), -1) {
		docker = append(docker, m[1])
	}
	sort.Strings(docker)
	reg := DNSProviderModules()
	if !reflect.DeepEqual(reg, docker) {
		t.Fatalf("registry vs Dockerfile mismatch:\n registry=%s\n docker  =%s",
			strings.Join(reg, ","), strings.Join(docker, ","))
	}
}

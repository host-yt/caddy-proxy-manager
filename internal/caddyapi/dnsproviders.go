package caddyapi

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

var (
	errUnknownProvider = errors.New("caddy: unknown DNS provider")
	errMissingField    = errors.New("caddy: missing required credential field")
)

// DNS provider registry: the SINGLE SOURCE OF TRUTH for the supported
// ACME DNS-01 providers. Consumed by the admin UI (dropdown + dynamic
// credential fields), by provider JSON emission (providerJSON below), and
// - kept in sync by hand - by the xcaddy module list in deploy/caddy/Dockerfile.
// Each CaddyModule MUST equal a built caddy-dns/<module>: a selected provider
// whose module is not in the image makes Caddy reject the WHOLE /load.

// CredField is one credential input for a provider. Key is the exact JSON
// key Caddy/libdns expects under challenges.dns.provider; Secret renders it
// write-only (password) and keeps it out of any has-credential display.
type CredField struct {
	Key         string
	Label       string
	Placeholder string
	Secret      bool
	Optional    bool
}

// DNSProvider is a registry entry. CaddyModule is the value emitted as the
// provider JSON "name" (e.g. "cloudflare", "route53", "googleclouddns").
type DNSProvider struct {
	Slug        string
	DisplayName string
	CaddyModule string
	Fields      []CredField
}

// dnsProviders is the registry, keyed by slug. Module names + field keys are
// verified against each caddy-dns/<module> wrapper and its libdns Provider
// struct json tags (NOT guessed); deviations from the api_token convention are
// noted inline. Slugs are stored in dns_providers.provider.
var dnsProviders = map[string]DNSProvider{
	"cloudflare": {
		Slug: "cloudflare", DisplayName: "Cloudflare", CaddyModule: "cloudflare",
		Fields: []CredField{
			{Key: "api_token", Label: "API token", Placeholder: "zone-scoped token (Zone:Read + DNS:Edit)", Secret: true},
		},
	},
	"route53": {
		Slug: "route53", DisplayName: "AWS Route 53", CaddyModule: "route53",
		// AWS creds optional: falls back to the instance/default credential chain.
		Fields: []CredField{
			{Key: "access_key_id", Label: "Access key ID", Secret: true, Optional: true},
			{Key: "secret_access_key", Label: "Secret access key", Secret: true, Optional: true},
			{Key: "region", Label: "Region", Placeholder: "us-east-1", Optional: true},
			{Key: "hosted_zone_id", Label: "Hosted zone ID", Optional: true},
		},
	},
	"googleclouddns": {
		Slug: "googleclouddns", DisplayName: "Google Cloud DNS", CaddyModule: "googleclouddns",
		Fields: []CredField{
			{Key: "gcp_project", Label: "GCP project ID", Placeholder: "my-project"},
			{Key: "gcp_application_default", Label: "Service account JSON", Placeholder: "{...} (omit to use ambient ADC)", Secret: true, Optional: true},
		},
	},
	"azure": {
		Slug: "azure", DisplayName: "Azure DNS", CaddyModule: "azure",
		// Omit tenant/client/secret to use a managed identity.
		Fields: []CredField{
			{Key: "subscription_id", Label: "Subscription ID"},
			{Key: "resource_group_name", Label: "Resource group"},
			{Key: "tenant_id", Label: "Tenant ID", Optional: true},
			{Key: "client_id", Label: "Client ID", Optional: true},
			{Key: "client_secret", Label: "Client secret", Secret: true, Optional: true},
		},
	},
	"digitalocean": {
		Slug: "digitalocean", DisplayName: "DigitalOcean", CaddyModule: "digitalocean",
		// Key is auth_token, not api_token.
		Fields: []CredField{
			{Key: "auth_token", Label: "API token", Secret: true},
		},
	},
	"hetzner": {
		Slug: "hetzner", DisplayName: "Hetzner", CaddyModule: "hetzner",
		Fields: []CredField{
			{Key: "api_token", Label: "API token", Secret: true},
		},
	},
	"linode": {
		Slug: "linode", DisplayName: "Linode", CaddyModule: "linode",
		Fields: []CredField{
			{Key: "api_token", Label: "API token (PAT)", Secret: true},
		},
	},
	"vultr": {
		Slug: "vultr", DisplayName: "Vultr", CaddyModule: "vultr",
		Fields: []CredField{
			{Key: "api_token", Label: "API key", Secret: true},
		},
	},
	"ovh": {
		Slug: "ovh", DisplayName: "OVH", CaddyModule: "ovh",
		Fields: []CredField{
			{Key: "endpoint", Label: "Endpoint", Placeholder: "ovh-eu"},
			{Key: "application_key", Label: "Application key", Secret: true},
			{Key: "application_secret", Label: "Application secret", Secret: true},
			{Key: "consumer_key", Label: "Consumer key", Secret: true},
		},
	},
	"gandi": {
		Slug: "gandi", DisplayName: "Gandi", CaddyModule: "gandi",
		// Key is bearer_token (Personal Access Token), not api_key.
		Fields: []CredField{
			{Key: "bearer_token", Label: "Personal access token", Secret: true},
		},
	},
	"namecheap": {
		Slug: "namecheap", DisplayName: "Namecheap", CaddyModule: "namecheap",
		Fields: []CredField{
			{Key: "api_key", Label: "API key", Secret: true},
			{Key: "user", Label: "API username"},
			{Key: "client_ip", Label: "Whitelisted client IP", Optional: true},
		},
	},
	"godaddy": {
		Slug: "godaddy", DisplayName: "GoDaddy", CaddyModule: "godaddy",
		// Single token in the form "<API_KEY>:<API_SECRET>".
		Fields: []CredField{
			{Key: "api_token", Label: "API token (KEY:SECRET)", Placeholder: "key:secret", Secret: true},
		},
	},
	"dnsimple": {
		Slug: "dnsimple", DisplayName: "DNSimple", CaddyModule: "dnsimple",
		Fields: []CredField{
			{Key: "api_access_token", Label: "API access token", Secret: true},
			{Key: "account_id", Label: "Account ID", Placeholder: "required only with a user token", Optional: true},
		},
	},
	"porkbun": {
		Slug: "porkbun", DisplayName: "Porkbun", CaddyModule: "porkbun",
		Fields: []CredField{
			{Key: "api_key", Label: "API key", Secret: true},
			{Key: "api_secret_key", Label: "Secret API key", Secret: true},
		},
	},
	"desec": {
		Slug: "desec", DisplayName: "deSEC", CaddyModule: "desec",
		// Single field key is token, not api_token.
		Fields: []CredField{
			{Key: "token", Label: "API token", Secret: true},
		},
	},
	"alidns": {
		Slug: "alidns", DisplayName: "Alibaba Cloud DNS", CaddyModule: "alidns",
		Fields: []CredField{
			{Key: "access_key_id", Label: "Access key ID", Secret: true},
			{Key: "access_key_secret", Label: "Access key secret", Secret: true},
		},
	},
	"netcup": {
		Slug: "netcup", DisplayName: "Netcup", CaddyModule: "netcup",
		Fields: []CredField{
			{Key: "customer_number", Label: "Customer number"},
			{Key: "api_key", Label: "API key", Secret: true},
			{Key: "api_password", Label: "API password", Secret: true},
		},
	},
	"powerdns": {
		Slug: "powerdns", DisplayName: "PowerDNS", CaddyModule: "powerdns",
		Fields: []CredField{
			{Key: "server_url", Label: "Server URL", Placeholder: "https://ns.example.com:8081"},
			{Key: "api_token", Label: "API token", Secret: true},
		},
	},
}

// DNSProviderBySlug returns the registry entry and whether it exists.
func DNSProviderBySlug(slug string) (DNSProvider, bool) {
	p, ok := dnsProviders[slug]
	return p, ok
}

// DNSProviders returns all registry entries sorted by DisplayName for stable
// UI rendering.
func DNSProviders() []DNSProvider {
	out := make([]DNSProvider, 0, len(dnsProviders))
	for _, p := range dnsProviders {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DisplayName < out[j].DisplayName })
	return out
}

// DNSProviderModules returns the unique CaddyModule names across the registry,
// sorted - the exact set the Dockerfile xcaddy line must build.
func DNSProviderModules() []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(dnsProviders))
	for _, p := range dnsProviders {
		if _, ok := seen[p.CaddyModule]; ok {
			continue
		}
		seen[p.CaddyModule] = struct{}{}
		out = append(out, p.CaddyModule)
	}
	sort.Strings(out)
	return out
}

// ValidateDNSFields checks a submitted field map against the provider's schema:
// rejects an unknown slug, drops unknown keys, and requires every non-optional
// field to be non-empty. Returns the cleaned map (registry keys only).
func ValidateDNSFields(slug string, fields map[string]string) (map[string]string, error) {
	p, ok := dnsProviders[slug]
	if !ok {
		return nil, errUnknownProvider
	}
	clean := make(map[string]string, len(p.Fields))
	for _, f := range p.Fields {
		v := strings.TrimSpace(fields[f.Key])
		if v == "" {
			if f.Optional {
				continue
			}
			return nil, errMissingField
		}
		clean[f.Key] = v
	}
	return clean, nil
}

// EncodeDNSFields serializes a validated field map to the JSON blob stored
// (encrypted) in dns_providers.api_token_enc.
func EncodeDNSFields(fields map[string]string) (string, error) {
	b, err := json.Marshal(fields)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// DecodeDNSFields parses a decrypted credential blob. Backward-compat: a legacy
// Cloudflare row holds a bare token (not JSON), so a non-JSON blob is treated
// as {"api_token": <blob>} for cloudflare; any other provider requires JSON.
func DecodeDNSFields(slug, blob string) map[string]string {
	var m map[string]string
	if err := json.Unmarshal([]byte(blob), &m); err == nil && m != nil {
		return m
	}
	if slug == "cloudflare" {
		return map[string]string{"api_token": blob}
	}
	return nil
}

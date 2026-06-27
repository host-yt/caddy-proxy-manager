# DNS-01 Challenge Providers

## Overview

HPG supports ACME DNS-01 challenges for wildcard TLS certificates (`*.example.com`).
DNS-01 requires the panel to create `_acme-challenge` TXT records via the DNS
provider's API; Caddy then completes the ACME handshake without needing HTTP-01
accessibility.

This is necessary for wildcard domains. Standard HTTP-01 challenges only work for
exact hostnames.

## Supported providers

The registry in `internal/caddyapi/dnsproviders.go` defines all supported providers.
Each entry maps a human-readable name to a `caddy-dns/<module>` name and the
credential fields the API expects.

| Display name | Slug | caddy-dns module |
|---|---|---|
| Alibaba Cloud DNS | `alidns` | `alidns` |
| AWS Route 53 | `route53` | `route53` |
| Azure DNS | `azure` | `azure` |
| Cloudflare | `cloudflare` | `cloudflare` |
| deSEC | `desec` | `desec` |
| DigitalOcean | `digitalocean` | `digitalocean` |
| DNSimple | `dnsimple` | `dnsimple` |
| Gandi | `gandi` | `gandi` |
| GoDaddy | `godaddy` | `godaddy` |
| Google Cloud DNS | `googleclouddns` | `googleclouddns` |
| Hetzner | `hetzner` | `hetzner` |
| Linode | `linode` | `linode` |
| Namecheap | `namecheap` | `namecheap` |
| Netcup | `netcup` | `netcup` |
| OVH | `ovh` | `ovh` |
| Porkbun | `porkbun` | `porkbun` |
| PowerDNS | `powerdns` | `powerdns` |
| Vultr | `vultr` | `vultr` |

Each `caddy-dns` module must be compiled into the Caddy binary used on each node.
The `deploy/caddy/Dockerfile` lists the exact xcaddy modules. Adding a provider to
the Go registry without adding it to the Dockerfile will cause Caddy to reject configs
that reference it.

## Configuration

1. In Admin → DNS Providers, click Add.
2. Select the provider from the dropdown. The form renders only the credential fields
   that provider requires.
3. Enter a name (used for reference on the host edit form) and the credentials.
   Secret fields (API keys, tokens) are stored encrypted at rest
   (`AES-256-GCM`, `api_token_enc` column in `dns_providers`).
4. Save.

### Credential notes by provider

- **AWS Route 53**: Access key and secret are optional when the instance has an IAM
  role or AWS credential chain configured; omit them to use ambient credentials.
- **Azure DNS**: Tenant, Client ID, and Client secret are optional when using a managed
  identity; only Subscription ID and Resource group are always required.
- **Google Cloud DNS**: `gcp_application_default` is optional when the container has
  Application Default Credentials available.
- **OVH**: Requires four fields: endpoint (e.g. `ovh-eu`), application key, application
  secret, and consumer key.

## Per-host setup

On the host edit form (Admin → Hosts → Edit), the Wildcard TLS section shows a
datalist of configured DNS provider names. Select one and enter the wildcard zone
(e.g. `example.com`). HPG tells Caddy to use DNS-01 for that hostname and all
`*.example.com` subdomains via that provider.

This only applies to routes that use a wildcard zone. Non-wildcard routes continue to
use HTTP-01 unless manually configured otherwise.

## Limitations

- The `caddy-dns` module for the selected provider must exist in the Caddy binary on
  every fleet node. A module missing from even one node will cause Caddy to reject the
  whole config on that node.
- dnspod and namedotcom are not supported (compile-time libdns incompatibility).
- DNS propagation delays affect how quickly ACME can verify the TXT record; this is
  outside HPG's control.
- Only one DNS provider can be assigned per wildcard zone per route.

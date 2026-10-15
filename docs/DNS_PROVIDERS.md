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
- **Cloudflare**: An API token with `Zone → Zone → Read` and `Zone → DNS → Edit` on the
  zone you issue the wildcard for. Paste the bare token: 35-50 characters of
  `A-Z a-z 0-9 _ -`, or a `cfut_` / `cfat_` prefixed token. Quotes, spaces or a
  `Bearer ` prefix are refused on save, and a stored token the Caddy DNS module would
  reject is skipped (the zone gets no DNS-01 policy) instead of failing the node's
  whole config load. This is a per-zone credential used by Caddy on the nodes, and is
  separate from the account-level token under Settings → Cloudflare - configure both
  if you use both features. See [`CLOUDFLARE.md`](CLOUDFLARE.md).
- **Azure DNS**: Tenant, Client ID, and Client secret are optional when using a managed
  identity; only Subscription ID and Resource group are always required.
- **Google Cloud DNS**: `gcp_application_default` is optional when the container has
  Application Default Credentials available.
- **OVH**: Requires four fields: endpoint (e.g. `ovh-eu`), application key, application
  secret, and consumer key.

## Per-host setup

On the host edit form (Admin → Hosts → Edit → SSL tab), tick wildcard DNS-01 and enter
the zone (e.g. `example.com`; it must cover the route's domain). The **name** of the
DNS provider row must equal the zone exactly (provider named `example.com` for zone
`example.com`).

All of these must hold, otherwise no wildcard cert is ordered:

- `DNS01_AVAILABLE=1` on the panel, and the route's node has a `caddy-dns` module
  (node page → Module capabilities; unprobed nodes follow `DNS01_AVAILABLE`).
- The Caddy image on the node is built with the provider's `caddy-dns` module.
- A DNS provider row named exactly as the zone, with a usable credential.
- SSL on, domain verified, route status `dns_ok`, `active` or `pending_ssl`.

The SSL tab lists every unmet condition. When all hold, the node orders `*.zone` and
`zone` as soon as the config loads (`tls.certificates.automate`), and **Renew
certificate now** re-pushes the full node config.

### Wildcard alias

To serve every subdomain from that one certificate, add the alias `*.<zone>` to the
route:

- Only the exact `*.<zone>` is accepted (one label deep); other wildcards are refused.
- Platform admins only. The route must have no path prefix.
- No TXT ownership proof is required for the wildcard alias.
- Subdomains are served from the single wildcard cert, never via on-demand TLS, so no
  per-subdomain certificates are issued.
- A route with an exact hostname for a subdomain wins over the wildcard.
- Access-log and WAF events for those subdomains are attributed to the route.
- Create the DNS record `*.<zone>` pointing at the node yourself. DNS steering manages
  only the route's main domain A/AAAA records (adding node IPs next to existing ones).

Non-wildcard routes keep using HTTP-01 / on-demand TLS.

## Limitations

- The `caddy-dns` module for the selected provider must exist in the Caddy binary on
  every fleet node. A module missing from even one node will cause Caddy to reject the
  whole config on that node.
- dnspod and namedotcom are not supported (compile-time libdns incompatibility).
- DNS propagation delays affect how quickly ACME can verify the TXT record; this is
  outside HPG's control.
- One DNS provider row per zone (names are matched to the zone), one zone per route.

# Cloudflare integration

Admin → Settings → Infrastructure → Cloudflare configures two independent things:

1. An account-level **API token** the panel uses to call the Cloudflare API.
2. A **Trust `CF-Connecting-IP`** toggle that makes the panel *and* every proxy
   node resolve the real client IP when traffic is proxied through Cloudflare.

Neither is the same as the per-zone DNS credential used for ACME DNS-01 wildcard
certificates. Those are configured per-domain under Admin → DNS Providers; see
[`DNS_PROVIDERS.md`](DNS_PROVIDERS.md).

## API token

### Which token type

Use a **user API token**, created at
`https://dash.cloudflare.com/profile/api-tokens` ("My Profile" → API Tokens →
Create Token).

These do **not** work and are rejected on save:

| Credential | Why it fails |
|---|---|
| Account-owned API token | Created under Account → API Tokens; not visible to the user token endpoint the panel verifies against |
| Global API Key (legacy) | Authenticates with `X-Auth-Key` + `X-Auth-Email`, not `Authorization: Bearer` |
| Origin CA key | Different auth scheme entirely |

The reported error for all of these is
`Cloudflare token rejected: Invalid API Token`.

### Which scopes

Saving verifies the token with `GET /client/v4/user/tokens/verify`, which needs
no particular permission - **any active user token passes today**, including the
"Read all resources" template.

Planned DNS automation will need `Zone → DNS → Edit` on the zones HPG manages,
so creating the token with that permission now avoids re-issuing it later. Scope
it to only the zones you intend HPG to touch.

The token is stored encrypted at rest (`AES-256-GCM`, `settings` table,
`cloudflare.api_token`). Leave the field blank on save to keep the existing token.

## Trust CF-Connecting-IP

When your hostnames are proxied through Cloudflare (orange cloud), every request
reaches HPG from a Cloudflare edge IP. Without this toggle, that edge IP is what
gets logged, matched, and forwarded upstream - the real visitor IP is only in the
`CF-Connecting-IP` header, which nothing reads.

Enabling the toggle changes two layers:

- **Panel** - the `CloudflareIP` middleware rewrites `RemoteAddr` from
  `CF-Connecting-IP`, so admin audit logs, brute-force lockouts, and per-IP rate
  limits act on the real client.
- **Proxy nodes** - the generated Caddy config sets, on the HTTP server:

  ```json
  "trusted_proxies": { "source": "static", "ranges": ["173.245.48.0/20", "..."] },
  "client_ip_headers": ["CF-Connecting-IP"]
  ```

  Caddy then resolves `client_ip` from the header for access logs (and therefore
  for HPG's analytics, world map, and WAF events) and forwards the real client
  address upstream in `X-Forwarded-For`.

Saving the settings form re-pushes the config to every enabled node, so the
change takes effect without waiting for the drift reconciler.

### Spoofing

The header is only honoured when the immediate peer is inside a published
Cloudflare edge range - both in the panel middleware and, via `trusted_proxies`,
in Caddy. A client connecting directly to your origin cannot fake its IP by
sending `CF-Connecting-IP`.

That guarantee assumes traffic actually reaches the node through Cloudflare. If
your origin is reachable by IP, anyone can bypass Cloudflare entirely; restrict
the origin firewall to Cloudflare's ranges (or use Cloudflare Tunnel) if that
matters to you.

The edge range list is bundled in `internal/cloudflare/ranges.go` rather than
fetched at runtime. Cloudflare changes it rarely; when they do, update that file
and redeploy.

### Per-host header workaround no longer needed

Earlier versions required setting custom upstream headers per host:

```
X-Real-IP: {http.request.header.CF-Connecting-IP}
X-Forwarded-For: {http.request.header.CF-Connecting-IP}
```

With the toggle enabled this is handled globally, and those manual entries can be
removed. They are unconditional - they rewrite the header even for requests that
did not come through Cloudflare, which is exactly the spoofing hole
`trusted_proxies` closes.

## Not using Cloudflare's proxy

Leave the toggle off if your DNS records are grey-clouded (DNS-only) or you do
not use Cloudflare at all. Nodes then see the true peer IP directly and no
`trusted_proxies` config is emitted.

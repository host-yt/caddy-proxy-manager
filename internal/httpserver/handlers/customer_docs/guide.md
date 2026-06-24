# Hostyt Proxy - Customer guide

Hands-on walkthrough for a client account. You map your own domains to
ports on your VPS through this panel; the panel runs the TLS termination
+ reverse-proxy fleet for you.

---

## 1. Your service

Your provider creates a **service** record for you with:

- a **backend IP** (your VPS's public IP, set by the provider)
- a **port range** (e.g. `30000-30019`) you can use
- a **plan** that defines limits (max domains, SSL, websockets, etc.)

You will never set or see the backend IP yourself. You just pick which of
your own application ports inside the range you want to expose.

## 2. Mapping a domain

1. Open **App → Routes → New route**.
2. Fill in:
   - **Domain** - your domain or subdomain, e.g. `app.example.com`.
   - **Path prefix** *(optional)* - leave blank for the whole host, or
     enter e.g. `/api` to only forward that path. (Path routing requires a
     plan that allows it.)
   - **Upstream port** - one of the ports in your service's range. This
     is the port on your VPS where your app actually listens.
   - **SSL** - leave on (recommended). Caddy issues a Let's Encrypt
     certificate automatically the first time someone visits.
   - **Force HTTPS** - keep on; cleartext requests are 308-redirected.
   - **WebSocket** - on if your app uses `wss://`.
3. Submit. The route lands as `pending_dns` while the panel waits for
   your DNS to point at the proxy.

## 3. Pointing DNS

Your provider gives you the proxy's public hostname (or IP). Add a record
to your DNS:

| Type  | Name              | Value                              |
| ----- | ----------------- | ---------------------------------- |
| CNAME | `app.example.com` | `fra.proxy.example.com.` *(yours)* |

Use `A` instead of `CNAME` if your provider gave you an IP literal, or if
the record is at the apex (`example.com`).

DNS takes anywhere from 1 minute to 1 hour to propagate. The panel checks
every 60 s and flips your route to `dns_ok` automatically once it sees
the right answer. You can also force a check from the row's **Verify DNS**
button.

## 4. TLS certificate

Once `dns_ok`, the next HTTPS request to your domain triggers Caddy's
**On-Demand TLS** flow: Caddy calls the panel's allowlist endpoint, gets
a green light, and asks Let's Encrypt for a certificate. This takes
~5–15 seconds. The route flips to `active`.

If you get a TLS handshake error, hit the route's **Retry SSL** button
and watch the status column. Common failure causes:

- DNS not propagated yet - wait, then retry.
- CAA record blocks Let's Encrypt - check your DNS provider for any
  `CAA` records and add `letsencrypt.org` if needed.
- Your domain is in a Public Suffix List entry that disallows wildcards -
  reach out to your provider.

## 5. Editing / deleting

- **Delete a route** - removes the mapping and tells Caddy to stop
  serving it. Existing certificates stay in storage for renewal up to
  90 days.
- **Change a route** - delete + re-create. (We deliberately keep editing
  minimal to avoid silent reconfiguration.)

## 6. 2FA

Open **App → 2FA**. Scan the QR with any TOTP app (Aegis, 1Password,
Authy, Google Authenticator). Save the recovery codes somewhere not on
the same device.

## 7. API access (optional)

If your provider grants you an API key, you can drive routes from your
own automation:

```bash
curl -H "Authorization: Bearer hpg_xxxxxxxxxxx" \
     https://panel.example.com/api/v1/services/123/routes
```

The full contract lives in `docs/API.md`. Endpoints are versioned at
`/api/v1` and use bearer-token auth; CSRF cookies are not required for
JSON requests.

## 8. Limits

Plans cap:

- **max_domains** - total routes per service.
- **max_ports** - distinct upstream ports you can use within your range.
- **path_routing** - whether you can use the path-prefix field.
- **wildcard** - whether you can map `*.example.com` (typically off).
- **websocket** - whether `wss://` upgrades pass through.
- **rate_limit_rpm** *(if set)* - requests/min per remote IP at the edge.

The panel surfaces the cap and current usage in **App → Services**.

## 9. Support

Reach your provider through the channel they gave you. The panel does
not bundle a ticketing system.

## 10. Privacy

Read the provider's policies at `/legal/privacy` and `/legal/tos`. The
panel implements:

- right to access - your provider can issue a one-shot JSON export of
  every row that mentions your account (see `/admin/users/{id}/gdpr-export`
  for the admin path).
- right to erasure - the provider can mask your account; routes you owned
  remain in audit logs with PII redacted, per data-protection law.

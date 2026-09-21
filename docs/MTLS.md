# Mutual TLS (Client Certificates)

## Overview

HPG supports mutual TLS (mTLS): the server asks clients to present a
certificate during the TLS handshake. Only clients with a certificate signed by a
configured CA are accepted. This is useful for machine-to-machine routes where
browser-based access is not expected.

Enforcement is per hostname, not per route or per path - see
[Per-hostname enforcement](#per-hostname-enforcement) below.

mTLS in HPG is implemented entirely through Caddy's `tls_connection_policies`; no
additional Caddy module is required. Stock Caddy supports this.

The env flag `MTLS_AVAILABLE` mentioned in older documentation controls whether the
feature is offered in the UI, but the TLS functionality itself works on stock Caddy.

## Certificate Authorities

HPG generates and manages CA certificates internally. Each CA is stored in the
`mtls_cas` table:

- The CA private key is encrypted at rest (AES-256-GCM via `installstate`).
- A CA can be scoped to a specific client (`client_id`) or be operator-wide (`NULL`).
- Each CA has a `serial_seq` counter used to issue unique serials for client certs.

### Creating a CA

Admin → Security → mTLS Authorities → Add CA. HPG generates the CA key pair and
self-signed cert. You can then issue client certificates from that CA or upload
your own CA cert if you already have a PKI.

### Issuing client certificates

From the CA detail page, issue a client cert. The issued cert and its status
(active / revoked) are stored in `mtls_issued_certs`. Revoking a cert here prevents
it from being used on any route that references this CA on the next Caddy config push.

## Per-hostname enforcement

On the host edit page, under mTLS:

1. Enable "Require client certificate".
2. Select a CA from the list of CAs available to this client.

HPG stores `mtls_ca_id` (FK to `mtls_cas.id`) and `require_client_cert` on the
route and includes the CA cert PEM in the emitted TLS connection policy for
that hostname.

Client-certificate enforcement is decided at the TLS handshake, before Caddy
has parsed a request path: Caddy picks a connection policy by SNI, and only
then does routing (host + path matching) happen. There is no per-path hook at
that point, so enforcement can only be a property of the hostname - turning
mTLS on for a host enforces it for every path served under that hostname.

If two routes share the same hostname (for example a base domain and a
`path_prefix` route on it) and disagree on enforcement, the builder merges
them into a single connection policy for that SNI: a non-enforcing route is
simply skipped rather than treated as an override, so if any route on the
hostname requires a client certificate the whole hostname is enforced. If more
than one enforcing route names a different CA, the first one processed wins
and the conflicting CA is dropped with a logged warning instead of silently
replacing it. In practice this means mTLS cannot be scoped to one
`path_prefix` route while leaving a sibling route on the same hostname open -
enable it on one and the whole hostname is covered.

An mTLS-enforced host also forces HTTPS. Enforcement lives entirely in the
TLS connection policy, so it never applied to the plaintext listener on port
80 - the host was reachable there with no client-cert check at all. `BuildRoute`
now derives `force_https` from `require_client_cert` on every route, closing
that gap regardless of the stored flag. Every write path that can set
`require_client_cert` (host create, the host edit page - also used by
reseller-scoped/tenant admins editing their own hosts - and
`PATCH /api/v1/routes/{id}`) keeps the stored `force_https` in sync so the
panel's display matches what the node serves. Migration `00145` backfills
`force_https = 1` on every route that already had `require_client_cert = 1`
before this change shipped.

The emitted server also pins `strict_sni_host` whenever any connection policy
requires a client certificate, so a request cannot reach the enforced host by
presenting a different, unenforced SNI and then sending the enforced host's
name in the `Host` header.

## SSL is required for enforcement

Client authentication is part of the route's TLS connection policy, so it has
no effect if the route serves plain HTTP: a host cannot be saved with
"Require client certificate" on and SSL off. Host create, the host edit page
(shared by reseller-scoped/tenant admins editing their own hosts), and
`PATCH /api/v1/routes/{id}` all refuse that combination - the API returns 400
with `cannot disable ssl_enabled while require_client_cert is set`; the admin
UI redirects back with a flash message asking to enable SSL or turn mTLS off.

A route that reached this state before the check existed cannot be pushed as
enforced: the host edit page shows it as "mTLS saved - SSL off, not enforced"
rather than "mTLS enforced", since there is no TLS connection policy to emit
for it. Turn SSL on (or off and re-verify) to resolve it.

## Fail-open vs fail-closed

Admin → Settings → mTLS has a global "Fail open" toggle:

| Setting | `client_authentication` mode in Caddy |
|---------|--------------------------------------|
| Fail closed (default) | `require_and_verify` - handshake fails if no valid cert |
| Fail open | `verify_if_given` - cert presented and verified if sent; no cert = allowed |

Fail-open relaxes the requirement to present a certificate, not the
requirement that a presented one be genuine: an invalid or self-signed
certificate still fails the handshake. Up to v1.5.0 the builder emitted
`request` here instead, which accepted any certificate without checking it -
and since the subject travels onward as `X-Mtls-Subject`, a client could claim
any identity. Fixed in v1.5.1.

Fail-open is intended for gradual rollout or debugging. For production use fail-closed.

The setting applies to all mTLS-enabled routes on a push.

## Caddy integration

HPG emits `tls_connection_policies` in the Caddy server config, not inside individual
routes. One policy entry is generated per mTLS-enabled route hostname with:

- `match.sni` set to the route's hostname(s)
- `client_authentication.trusted_ca_certs` containing the CA cert(s) as base64 DER
- `client_authentication.mode` set by the fail-open/closed toggle

A catch-all policy at the end allows non-mTLS routes to use default TLS.

## Limitations

- Enforcement is per hostname, not per route or per URI path. It is decided by
  the TLS connection policy matched on SNI, before Caddy has any request path
  to match against - see [Per-hostname enforcement](#per-hostname-enforcement).
  Turning mTLS on for a host covers every path served under that hostname.
- Certificate revocation is handled by HPG state only (no OCSP/CRL endpoint is
  published). A revoked cert takes effect on the next Caddy config push.
- The CA private key is stored encrypted in the database. Back up `APP_SECRET` and the
  database together; losing either makes CA key recovery impossible.
- Browser clients require manual import of the client certificate and the CA cert.

# Mutual TLS (Client Certificates)

## Overview

HPG supports per-route mutual TLS (mTLS): the server asks clients to present a
certificate during the TLS handshake. Only clients with a certificate signed by a
configured CA are accepted. This is useful for machine-to-machine routes where
browser-based access is not expected.

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

## Per-route configuration

On the host edit page, under mTLS:

1. Enable "Require client certificate".
2. Select a CA from the list of CAs available to this client.

HPG stores `mtls_ca_id` (FK to `mtls_cas.id`) on the route and includes the CA cert
PEM in the emitted `tls_connection_policy` block for that hostname.

## Fail-open vs fail-closed

Admin → Settings → mTLS has a global "Fail open" toggle:

| Setting | `client_authentication` mode in Caddy |
|---------|--------------------------------------|
| Fail closed (default) | `require_and_verify` - handshake fails if no valid cert |
| Fail open | `verify_if_given` - cert presented and verified if sent; no cert = allowed |

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

- mTLS operates at the TLS layer; it cannot be applied selectively per URI path on
  the same hostname.
- Certificate revocation is handled by HPG state only (no OCSP/CRL endpoint is
  published). A revoked cert takes effect on the next Caddy config push.
- The CA private key is stored encrypted in the database. Back up `APP_SECRET` and the
  database together; losing either makes CA key recovery impossible.
- Browser clients require manual import of the client certificate and the CA cert.

# Manual TLS Certificates

Import your own TLS certificate + private key and have the edge serve it for a
domain **without ACME**. Use this for:

- domains behind a **private / internal CA** that public ACME can't validate,
- **pre-issued** or **commercial** certificates you already bought,
- air-gapped / internal hosts that never resolve on the public internet,
- a wildcard you obtain and rotate yourself.

For automatic Let's Encrypt / ZeroSSL issuance use on-demand TLS or DNS-01
wildcards instead - see [INSTALL.md](INSTALL.md) and
[DNS_PROVIDERS.md](DNS_PROVIDERS.md). Manual certs and ACME coexist: a manually
loaded certificate matches its SNI before the on-demand path, so a domain with a
manual cert never attempts issuance.

## Import a certificate

**Admin → Manual Certificates.**

1. Paste the **Certificate PEM** (leaf), the **Private key PEM**, and optionally
   the **Chain PEM** (intermediate CAs). The key is validated against the
   certificate on import - a mismatch is rejected.
2. Set **Linked proxy route ID** to the route this cert should serve. This is
   what makes it get served (see below).
3. Import. The common name, SANs, and validity window are parsed and shown; the
   private key is encrypted at rest (AES-256-GCM).

## Serving model

A manual certificate is served **only when it is linked to a route**:

- **Linked to a route** → the cert is pushed to every node that serves that
  route (its direct node plus any node-group fan-out) and loaded into Caddy's
  cert pool (`apps.tls.certificates.load_pem`). The node serves it for the
  route's domain over TLS. Import, replace, and delete re-push the affected
  node(s) automatically.
- **Not linked** → the cert is stored and expiry-monitored only. Nothing serves
  it. Link it to a route later to start serving.

Requirements for serving:

- the linked route must be **SSL-enabled** and in an active state
  (`dns_ok` / `active` / `pending_ssl`) - the same condition under which the
  route itself is emitted to the node;
- the certificate's SAN/CN must cover the route's domain (Caddy matches by SNI).

## Replace / rotate

Use **Replace** on an existing cert to swap in a new PEM in one step - the new
cert is imported and validated first, and only then is the old one removed, so a
bad paste never takes down the live cert. The linked route's node re-pushes with
the new material.

## Expiry monitoring

Certs within 30 days of expiry are flagged on the page, and the alert rule
`manual_cert_expiry` fires (configurable window under **Admin → Settings →
Alerts**). Manual certs are **not** auto-renewed - rotate them yourself before
they expire.

## Security

- Private keys are encrypted at rest with the app secret (AES-256-GCM).
- The key is decrypted only at config-push time and travels to the node over the
  same authenticated Caddy Admin API channel as every other secret (proxy
  bearer tokens, DNS-01 credentials). It is never written to logs.

## Verify

After linking a cert to an SSL route, confirm the edge presents it:

```sh
openssl s_client -connect <edge-host>:443 -servername app.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -serial
```

The subject/serial must match the certificate you imported. You can also inspect
the pushed node config: `apps.tls.certificates.load_pem` contains the cert, and
a request over HTTPS terminates on it and proxies to the backend.
